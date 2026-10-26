package manifest

import "testing"

func TestParseMavenPathGroupLevelID(t *testing.T) {
	t.Parallel()
	cases := []struct {
		path, name, groupLevel string
	}{
		{"org/apache/maven/plugins/maven-metadata.xml", "org.apache.maven:plugins", "org.apache.maven.plugins"},
		{"org/apache/maven/plugins/maven-metadata.xml.sha1", "org.apache.maven:plugins", "org.apache.maven.plugins"},
		{"org/springframework/boot/spring-boot/maven-metadata.xml", "org.springframework.boot:spring-boot", "org.springframework.boot.spring-boot"},
		{"org/example/core/widget/1.3.0-SNAPSHOT/maven-metadata.xml", "org.example.core:widget", ""},
		{"org/example/core/widget/1.3.0-SNAPSHOT/maven-metadata.xml.md5", "org.example.core:widget", ""},
		{"org/example/core/widget/1.2.0/widget-1.2.0.jar", "org.example.core:widget", ""},
		{"org/example/core/widget/1.2.0/widget-1.2.0.pom.sha1", "org.example.core:widget", ""},
	}
	for _, c := range cases {
		mp, ok := ParseMavenPath(c.path)
		if !ok {
			t.Errorf("ParseMavenPath(%q) refused a layout path", c.path)
			continue
		}
		if mp.Name() != c.name || mp.GroupLevelID != c.groupLevel {
			t.Errorf("ParseMavenPath(%q) = %s with GroupLevelID %q; want %s with %q", c.path, mp.Name(), mp.GroupLevelID, c.name, c.groupLevel)
		}
		wantGroupName := ""
		if c.groupLevel != "" {
			wantGroupName = c.groupLevel + ":*"
		}
		if got := mp.GroupLevelName(); got != wantGroupName {
			t.Errorf("GroupLevelName(%q) = %q, want %q", c.path, got, wantGroupName)
		}
	}
}

// A version publishes whatever extension its packaging names, so the parse
// takes the extension from the file name rather than from a list.
func TestParseMavenPathAnyExtension(t *testing.T) {
	t.Parallel()
	cases := []struct {
		path string
		want MavenPath
	}{
		{"org/apache/maven/apache-maven/3.9.16/apache-maven-3.9.16-bin.tar.gz",
			MavenPath{GroupID: "org.apache.maven", ArtifactID: "apache-maven", Version: "3.9.16", Classifier: "bin", Extension: "tar.gz"}},
		{"org/apache/maven/apache-maven/3.9.16/apache-maven-3.9.16-bin.zip",
			MavenPath{GroupID: "org.apache.maven", ArtifactID: "apache-maven", Version: "3.9.16", Classifier: "bin", Extension: "zip"}},
		{"org/apache/maven/apache-maven/3.9.16/apache-maven-3.9.16-bin.tar.gz.sha512",
			MavenPath{GroupID: "org.apache.maven", ArtifactID: "apache-maven", Version: "3.9.16", Classifier: "bin", Extension: "tar.gz", Companion: "sha512"}},
		{"com/google/protobuf/protoc/4.31.1/protoc-4.31.1-linux-x86_64.exe",
			MavenPath{GroupID: "com.google.protobuf", ArtifactID: "protoc", Version: "4.31.1", Classifier: "linux-x86_64", Extension: "exe"}},
	}
	for _, c := range cases {
		got, ok := ParseMavenPath(c.path)
		if !ok || got != c.want {
			t.Errorf("ParseMavenPath(%q) = %+v, %v; want %+v", c.path, got, ok, c.want)
		}
	}
	for _, p := range []string{
		"org/example/widget/1.0/widget-1.0",               // no extension
		"org/example/widget/1.0/widget-1.0-bin",           // no dot after the classifier
		"org/example/widget/1.0/widget-1.0-.zip",          // empty classifier
		"org/example/widget/1.0/widget-1.0-bin.",          // empty extension
		"org/example/widget/1.0/widget-1.0.tar..gz",       // empty extension part
		"org/example/widget/1.0/widget-1.0.jar.sha1.sha1", // companion of a companion
		"org/example/widget/1.0/widget-1.0x.jar",          // version runs on past its directory
	} {
		if got, ok := ParseMavenPath(p); ok {
			t.Errorf("ParseMavenPath(%q) = %+v, want refused", p, got)
		}
	}
}
