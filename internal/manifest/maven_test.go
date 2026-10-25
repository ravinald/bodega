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
