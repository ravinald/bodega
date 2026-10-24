package clientconf

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
)

// F87 R1: settings.xml mirrors every repository to <base>/maven/, and the
// init script replaces every repository a build names with the same URL.
func TestMavenRendersSettingsAndGradleInit(t *testing.T) {
	files := Maven("https://bodega.internal/", nil)
	if len(files) != 2 {
		t.Fatalf("Maven rendered %d files, want settings.xml and the init script", len(files))
	}
	settings, gradle := files[0], files[1]
	if settings.System != manifest.TypeMaven || settings.Path(OSLinux) != MavenSettingsPath || gradle.Path(OSDarwin) != GradleInitPath {
		t.Errorf("paths = %q, %q", settings.Path(OSLinux), gradle.Path(OSDarwin))
	}
	var parsed struct {
		Mirrors []struct {
			ID       string `xml:"id"`
			MirrorOf string `xml:"mirrorOf"`
			URL      string `xml:"url"`
		} `xml:"mirrors>mirror"`
	}
	if err := xml.Unmarshal([]byte(settings.Content), &parsed); err != nil {
		t.Fatalf("settings.xml does not parse: %v\n%s", err, settings.Content)
	}
	if len(parsed.Mirrors) != 1 || parsed.Mirrors[0].MirrorOf != "*" || parsed.Mirrors[0].URL != "https://bodega.internal/maven/" {
		t.Errorf("mirrors = %+v, want one mirror of * at https://bodega.internal/maven/", parsed.Mirrors)
	}
	for _, want := range []string{
		"def bodegaUrl = 'https://bodega.internal/maven/'",
		"beforeSettings",
		"settings.pluginManagement.repositories",
		"settings.buildscript.repositories",
		"settings.dependencyResolutionManagement.repositories",
		"project.buildscript.repositories",
		"repos.remove(repo)",
	} {
		if !strings.Contains(gradle.Content, want) {
			t.Errorf("init script lacks %q:\n%s", want, gradle.Content)
		}
	}
	if strings.Contains(gradle.Content, "allowInsecureProtocol") {
		t.Error("an https base allows an insecure protocol")
	}
	if plain := Maven("http://bodega.internal:8080", nil)[1].Content; !strings.Contains(plain, "allowInsecureProtocol = true") {
		t.Errorf("an http base does not allow it, and Gradle refuses an http repository without it:\n%s", plain)
	}
}

// F87 R3: the notes name the distributionUrl for each wrapper, through the
// binary_upstreams namespace on the wrapper's own host when one exists.
func TestMavenWrapperNotesNameTheNamespace(t *testing.T) {
	none := strings.Join(MavenWrapperNotes("https://b", nil), "\n")
	for _, want := range []string{
		".mvn/wrapper/maven-wrapper.properties", "gradle/wrapper/gradle-wrapper.properties",
		"distributionUrl=https://b/binaries/<namespace>/org/apache/maven/apache-maven/<version>/apache-maven-<version>-bin.zip",
		"distributionUrl=https://b/binaries/<namespace>/distributions/gradle-<version>-bin.zip",
		"whose url is https://repo.maven.apache.org/maven2/", "whose url is https://services.gradle.org/",
		"doctor does not edit",
	} {
		if !strings.Contains(none, want) {
			t.Errorf("notes with no namespace lack %q:\n%s", want, none)
		}
	}
	ups := map[string]config.BinaryUpstream{
		"central": {URL: "https://repo.maven.apache.org/maven2", Mode: config.UpstreamModeOpen},
		"gradle":  {URL: "https://services.gradle.org/", Mode: config.UpstreamModeCatalog},
		"node":    {URL: "https://nodejs.org/", Mode: config.UpstreamModeOpen},
	}
	some := MavenWrapperNotes("https://b", ups)
	if !strings.Contains(some[0], "https://b/binaries/central/org/apache/maven/") || strings.Contains(some[0], "once") {
		t.Errorf("Maven note with an open namespace = %q", some[0])
	}
	if !strings.Contains(some[1], "https://b/binaries/gradle/distributions/") || !strings.Contains(some[1], `binary_upstreams["gradle"] is in open mode`) {
		t.Errorf("Gradle note with a catalog namespace = %q", some[1])
	}
}

// F87 R2: the merge replaces the mirrors and keeps every other byte.
func TestMergeMavenSettings(t *testing.T) {
	planned := []byte(Maven("https://b", nil)[0].Content)
	block := "<mirrors>\n    <mirror>\n      <id>bodega</id>\n      <mirrorOf>*</mirrorOf>\n      <url>https://b/maven/</url>\n    </mirror>\n  </mirrors>"
	head := `<?xml version="1.0" encoding="UTF-8"?>` + "\n" + `<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0">` + "\n"
	servers := "  <servers>\n    <server><id>corp</id><password>p</password></server>\n  </servers>\n"
	profiles := "  <profiles>\n    <profile><id>extra</id><repositories><repository><id>o</id><url>https://o/</url></repository></repositories></profile>\n  </profiles>\n"
	comment := "  <!-- <mirrors><mirror><id>example</id></mirror></mirrors> -->\n"
	cases := []struct{ name, existing, want string }{
		{
			"an existing mirror and profile",
			head + servers + "  <mirrors>\n    <mirror><id>nexus</id><mirrorOf>central</mirrorOf><url>https://n/</url></mirror>\n  </mirrors>\n" + profiles + "</settings>\n",
			head + servers + "  " + block + "\n" + profiles + "</settings>\n",
		},
		{
			"a commented example before the live element",
			head + comment + "  <mirrors>\n  </mirrors>\n" + profiles + "</settings>\n",
			head + comment + "  " + block + "\n" + profiles + "</settings>\n",
		},
		{
			"no mirrors, only a commented example",
			head + comment + profiles + "</settings>",
			head + comment + profiles + "  " + block + "\n</settings>\n",
		},
		{"an empty mirrors element", head + "  <mirrors/>\n</settings>\n", head + "  " + block + "\n</settings>\n"},
		{"an empty file", "\n", string(planned)},
		{"not a settings file", "junk\n", string(planned)},
		{"an unclosed mirrors element", head + "  <mirrors>\n</settings>\n", string(planned)},
	}
	for _, tc := range cases {
		got := string(MergeMavenSettings([]byte(tc.existing), planned))
		if got != tc.want {
			t.Errorf("%s:\ngot:\n%s\nwant:\n%s", tc.name, got, tc.want)
		}
		if again := string(MergeMavenSettings([]byte(got), planned)); again != got {
			t.Errorf("%s: a second merge changed the file:\n%s", tc.name, again)
		}
	}
}

// A plan applied over an existing settings.xml merges into it; the init
// script, bodega's own file, is replaced.
func TestNewChangeMergesMavenSettingsAndReplacesTheInitScript(t *testing.T) {
	home := t.TempDir()
	files := Maven("https://b", nil)
	existing := "<settings>\n  <profiles><profile><id>keep</id></profile></profiles>\n</settings>\n"
	writeHomeFile(t, home, ".m2/settings.xml", existing)
	writeHomeFile(t, home, ".gradle/init.d/bodega.gradle", "// stale\n")
	for _, f := range files {
		rec := PlanRecord{System: manifest.TypeMaven, Action: PlanInstall, Path: f.Path(OSLinux), SHA256: digest(f.Content)}
		c, err := NewChange(rec, []byte(f.Content), home)
		if err != nil {
			t.Fatal(err)
		}
		switch rec.Path {
		case MavenSettingsPath:
			if !strings.Contains(string(c.New), "<id>keep</id>") || !strings.Contains(string(c.New), "<mirrorOf>*</mirrorOf>") {
				t.Errorf("settings.xml change = %q, want the profile kept and the mirror added", c.New)
			}
		case GradleInitPath:
			if string(c.New) != f.Content {
				t.Errorf("init script change = %q, want the planned file whole", c.New)
			}
		}
	}
}

func writeHomeFile(t *testing.T, home, rel, content string) {
	t.Helper()
	p := filepath.Join(home, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
