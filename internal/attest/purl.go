package attest

import (
	"path"
	"strings"

	"github.com/ravinald/bodega/internal/manifest"
)

// PURL returns the package URL a subject is named by. objectKey only matters
// for pypi and maven, where one release is several files: pypi's file_name
// qualifier and maven's classifier and type say which one this digest is over.
//
// Ecosystems with a registered purl type use it, rubygems as pkg:gem, maven
// as pkg:maven/<groupId>/<artifactId> and composer as
// pkg:composer/<vendor>/<package>, lowercased as that type requires. The rest (apt, binary, git,
// helm, freebsd, distfiles) are named pkg:generic/<bodega type>/<name>: a deb
// purl needs the distribution vendor as its namespace, which a bodega apt
// entry does not record, and a guessed vendor would name a package somebody
// else built.
func PURL(typ, name, version, objectKey string) string {
	var b strings.Builder
	b.WriteString("pkg:")
	switch typ {
	case manifest.TypeNpm:
		b.WriteString("npm/")
		if scope, rest, ok := strings.Cut(name, "/"); ok && strings.HasPrefix(scope, "@") {
			b.WriteString(purlEscape(scope) + "/")
			name = rest
		}
		b.WriteString(purlEscape(name))
	case manifest.TypePypi:
		b.WriteString("pypi/" + purlEscape(manifest.CanonicalPypiName(name)))
	case manifest.TypeGomod:
		segs := strings.Split(name, "/")
		for i, s := range segs {
			segs[i] = purlEscape(s)
		}
		b.WriteString("golang/" + strings.Join(segs, "/"))
	case manifest.TypeCargo:
		b.WriteString("cargo/" + purlEscape(name))
	case manifest.TypeRubygems:
		b.WriteString("gem/" + purlEscape(name))
	case manifest.TypeMaven:
		if group, artifact, ok := strings.Cut(name, ":"); ok {
			b.WriteString("maven/" + purlEscape(group) + "/" + purlEscape(artifact))
		} else {
			b.WriteString("maven/" + purlEscape(name))
		}
	case manifest.TypeComposer:
		b.WriteString("composer/")
		if vendor, pkg, ok := strings.Cut(strings.ToLower(name), "/"); ok {
			b.WriteString(purlEscape(vendor) + "/" + purlEscape(pkg))
		} else {
			b.WriteString(purlEscape(strings.ToLower(name)))
		}
	default:
		b.WriteString("generic/" + purlEscape(typ) + "/" + purlEscape(name))
	}
	// A platform gem's version as bodega records it carries the build
	// ("1.16.7-x86_64-linux"); the gem purl type moves it to a qualifier.
	var platform string
	if typ == manifest.TypeRubygems {
		version, platform = manifest.RubygemsPlatform(version)
	}
	if version != "" {
		b.WriteString("@" + purlEscape(version))
	}
	if platform != "" {
		b.WriteString("?platform=" + purlEscape(platform))
	}
	if typ == manifest.TypePypi && strings.HasPrefix(objectKey, manifest.PypiWheelPrefix) {
		b.WriteString("?file_name=" + purlEscape(path.Base(objectKey)))
	}
	if typ == manifest.TypeMaven {
		b.WriteString(mavenQualifiers(objectKey))
	}
	return b.String()
}

// PURLBase strips the qualifiers and subpath, which is the part a verifier
// compares against the package and version it asked about.
func PURLBase(purl string) string {
	if i := strings.IndexAny(purl, "?#"); i >= 0 {
		return purl[:i]
	}
	return purl
}

// purlEscape percent-encodes everything outside the purl spec's unreserved
// set, ':' excepted: the spec leaves it literal, and a Debian epoch or a
// FreeBSD ABI carries one.
func purlEscape(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9',
			c == '-', c == '.', c == '_', c == '~', c == ':':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&15])
		}
	}
	return b.String()
}

// mavenQualifiers names which file of a version objectKey is, in the
// qualifiers' sorted order. The maven purl type's type defaults to jar, so a
// jar without a classifier, the file most versions are known by, carries
// none.
func mavenQualifiers(objectKey string) string {
	rel, ok := strings.CutPrefix(objectKey, manifest.MavenKey(""))
	if !ok {
		return ""
	}
	mp, ok := manifest.ParseMavenPath(rel)
	if !ok || mp.Metadata {
		return ""
	}
	var q []string
	if mp.Classifier != "" {
		q = append(q, "classifier="+purlEscape(mp.Classifier))
	}
	if mp.Extension != "jar" {
		q = append(q, "type="+purlEscape(mp.Extension))
	}
	if len(q) == 0 {
		return ""
	}
	return "?" + strings.Join(q, "&")
}
