package manifest

import (
	"strings"
	"testing"
)

// roundTrip is one type's constructor output and the identity ParseKey must
// read back out of it.
type roundTrip struct {
	key     string
	name    string
	version string
}

// keyRoundTrips holds at least one case per member of AllTypes, built by the
// constructor rather than by a hand-written string: a key literal would keep
// passing after the constructor changed the layout underneath it.
//
// Every type whose encoding can alter a name carries a name that exercises it.
// npm, git and binary get one with a slash; helm and cargo get one with a
// literal "--", which SafeName never produces for them and unsafeName used to
// decode back to a slash on the way out.
//
// pypi is the one entry with no constructor. Wheels upload as a directory and
// ArtifactKeys answers ErrPypiNoObjectKey for them, so the key here is built
// from PypiWheelPrefix the way the sync writes it.
var keyRoundTrips = map[string][]roundTrip{
	TypeBinary: {
		{
			key:     BinaryKey("example-tool", "2.15.0", "example-toolv2.zip"),
			name:    "example-tool",
			version: "2.15.0",
		},
	},
	TypeGit: {
		{
			key:     GitKey("github.com/ravinald/bodega", "v1.2.0", false),
			name:    "github.com/ravinald/bodega",
			version: "v1.2.0",
		},
	},
	TypeApt: {
		{
			key:     AptKey("pool/main/n/nginx/nginx_1.24.0-2ubuntu7.1_amd64.deb"),
			name:    "nginx",
			version: "1.24.0-2ubuntu7.1",
		},
	},
	TypePypi: {
		{
			key:     PypiWheelPrefix + "1.26.0/examplesdk-1.26.0-py3-none-any.whl",
			name:    "examplesdk",
			version: "1.26.0",
		},
	},
	TypeGomod: {
		{
			key:     GomodKey("example.com/example-corp/widget-sdk", "v1.30.0", ".zip"),
			name:    "example.com/example-corp/widget-sdk",
			version: "v1.30.0",
		},
	},
	TypeHelm: {
		{
			key:     HelmChartKey("ingress-nginx", "4.11.2"),
			name:    "ingress-nginx",
			version: "4.11.2",
		},
		// A chart name cannot hold a slash, so "--" in one is literal.
		// Decoding it named the chart foo/bar in the discovery row and the
		// serve_fetch event. The lookup itself survived, SafeName being
		// applied again on the way to the manifest, so the damage was
		// confined to what an operator reads back.
		{
			key:     HelmChartKey("foo--bar", "1.2.3"),
			name:    "foo--bar",
			version: "1.2.3",
		},
	},
	TypeNpm: {
		{
			key:     NpmTarballKey("@example-corp/widget-cli", "1.4.2"),
			name:    "@example-corp/widget-cli",
			version: "1.4.2",
		},
	},
	TypeCargo: {
		{
			key:     CargoCrateKey("serde", "1.0.210"),
			name:    "serde",
			version: "1.0.210",
		},
		// Same for a crate name: "--" is two hyphens, not an encoded "/".
		{
			key:     CargoCrateKey("foo--bar", "1.2.3"),
			name:    "foo--bar",
			version: "1.2.3",
		},
	},
	TypeComposer: {
		{
			key:     ComposerDistKey("symfony/console", "v7.1.5", "0a3bd4fd5bcb6d5b4b9d1b5d9e0e7c9f1f0f8a3c"),
			name:    "symfony/console",
			version: "v7.1.5",
		},
		// A branch version holds a "/", which the key escapes so the four
		// segments stay four.
		{
			key:     ComposerDistKey("monolog/monolog", "dev-feature/x", "abc123"),
			name:    "monolog/monolog",
			version: "dev-feature/x",
		},
		{key: ComposerMetadataKey("symfony/console", false), name: "symfony/console"},
		{key: ComposerMetadataKey("symfony/console", true), name: "symfony/console"},
	},
	TypeRpm: {
		{key: RpmPackageKey("rocky-baseos", "9", "x86_64", "nginx", "2:1.20.1-20.el9", "nginx-1.20.1-20.el9.x86_64.rpm"), name: "nginx", version: "2:1.20.1-20.el9"},
		{key: RpmPackageKey("epel", "9", "noarch", "python3.12-foo", "1.0-1.el9", "python3.12-foo-1.0-1.el9.noarch.rpm"), name: "python3.12-foo", version: "1.0-1.el9"},
		// repomd.xml and the metadata it names belong to a repository, not a
		// package.
		{key: RpmRepomdKey("rocky-baseos", "9", "x86_64")},
		{key: RpmMetadataKey("rocky-baseos", "9", "x86_64", "c5f5", "c5f5-primary.xml.gz")},
	},
	TypeOCI: {
		{key: OCIManifestKey("docker.io", "library/nginx", "sha256:abababababababababababababababababababababababababababababababab"), name: "docker.io/library/nginx", version: "sha256:abababababababababababababababababababababababababababababababab"},
		{key: OCITagKey("ghcr.io", "acme/widget", "v4.1"), name: "ghcr.io/acme/widget", version: "v4.1"},
		{key: OCIResolvedKey("quay.io", "a/b/c", "sha256:abababababababababababababababababababababababababababababababab"), name: "quay.io/a/b/c", version: "sha256:abababababababababababababababababababababababababababababababab"},
		{key: OCIResolvedByKey("quay.io", "a/b/c", "sha256:abababababababababababababababababababababababababababababababab", "17"), name: "quay.io/a/b/c", version: "sha256:abababababababababababababababababababababababababababababababab"},
		{key: OCITagListKey("docker.io", "library/nginx"), name: "docker.io/library/nginx"},
		{key: OCIChartBlobKey("docker.io", "bitnamicharts/redis", "sha256:abababababababababababababababababababababababababababababababab", "sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"), name: "docker.io/bitnamicharts/redis"},
		{key: OCIUnsettledKey("docker.io", "library/nginx", "sha256:abababababababababababababababababababababababababababababababab", "sha256:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"), name: "docker.io/library/nginx"},
		{key: OCIManifestTypeKey("ghcr.io", "acme/widget", "sha256:abababababababababababababababababababababababababababababababab"), name: "ghcr.io/acme/widget"},
		// A blob is shared by every repository and names none.
		{key: OCIBlobKey("sha256:abababababababababababababababababababababababababababababababab"), version: "sha256:abababababababababababababababababababababababababababababababab"},
	},
	TypeRubygems: {
		{
			key:     RubygemsGemKey("concurrent-ruby", "1.3.4"),
			name:    "concurrent-ruby",
			version: "1.3.4",
		},
		// A platform build keeps its suffix as part of the version, which is
		// how the file is named and what tells it apart from the pure-Ruby gem.
		{
			key:     RubygemsGemKey("nokogiri", "1.16.7-x86_64-linux"),
			name:    "nokogiri",
			version: "1.16.7-x86_64-linux",
		},
		{
			key:     RubygemsSpecKey("concurrent-ruby-1.3.4.gemspec.rz"),
			name:    "concurrent-ruby",
			version: "1.3.4",
		},
	},
	TypeFreeBSD: {
		// latest/: the catalogue's repopath carries "~" and "$", and the ABI
		// directory carries colons. All of it survives into the key, so a
		// scheme that rejected any of the three would fail here rather than
		// against pkg.freebsd.org.
		{
			key:     FreeBSDKey("FreeBSD:14:amd64", "latest", "All/Hashed/zogftw-2025.02.23_1~2$snxfrbid.pkg"),
			name:    "latest",
			version: "FreeBSD:14:amd64",
		},
		// base_latest/: packages sit at the repository root, so the repopath
		// is one segment and the split must still find the ABI and the repo.
		{
			key:     FreeBSDKey("FreeBSD:14:amd64", "base_latest", "FreeBSD-kernel-generic-14.2.p1.pkg"),
			name:    "base_latest",
			version: "FreeBSD:14:amd64",
		},
		{
			key:     FreeBSDKey("FreeBSD:14:amd64", "latest", FreeBSDCatalogFile),
			name:    "latest",
			version: "FreeBSD:14:amd64",
		},
	},
	TypeMaven: {
		// The groupId's directories rejoin with dots, and every companion of
		// one version reads back as that version.
		{
			key:     MavenKey("org/apache/commons/commons-lang3/3.14.0/commons-lang3-3.14.0.jar.sha1"),
			name:    "org.apache.commons:commons-lang3",
			version: "3.14.0",
		},
		// Artifact-level metadata names no version.
		{
			key:  MavenKey("org/apache/commons/commons-lang3/maven-metadata.xml"),
			name: "org.apache.commons:commons-lang3",
		},
	},
	TypeDistfiles: {
		// A port with no DIST_SUBDIR: the name is the bare file, and the
		// version inside it stays in the name.
		{
			key:  DistfilesKey("zsh-5.9.2.tar.xz"),
			name: "zsh-5.9.2.tar.xz",
		},
		// A port that sets DIST_SUBDIR: the subdirectory survives the round
		// trip, because it is part of the name distinfo records.
		{
			key:  DistfilesKey("pcpustat/1.6.tar.bz2"),
			name: "pcpustat/1.6.tar.bz2",
		},
	},
}

// TestParseKeyRoundTripsEveryType is the guard on the pair. A ninth type added
// with a constructor and no ParseKey arm fails here rather than in production,
// where it costs every artifact of that type its package identity and
// `bodega pkg checksum clear` its only filter.
func TestParseKeyRoundTripsEveryType(t *testing.T) {
	for _, typ := range AllTypes {
		cases, ok := keyRoundTrips[typ]
		if !ok || len(cases) == 0 {
			t.Errorf("type %q is in AllTypes with no round-trip case: build its key with the constructor and add the ParseKey arm that reads it back", typ)
			continue
		}
		for _, want := range cases {
			gotType, gotName, gotVersion := ParseKey(want.key)
			if gotType != typ || gotName != want.name || gotVersion != want.version {
				t.Errorf("ParseKey(%q) = (%q, %q, %q), want (%q, %q, %q)",
					want.key, gotType, gotName, gotVersion, typ, want.name, want.version)
			}
		}
	}
	for typ := range keyRoundTrips {
		if !IsKnownType(typ) {
			t.Errorf("round-trip case for %q, which is not in AllTypes", typ)
		}
	}
}

// The trees carry regenerable siblings beside their artifacts. Each is its own
// type with no version — the type is what routes a row, and an index that came
// back untyped would sit in the table unreachable by any filter.
func TestParseKeyReadsGeneratedSiblings(t *testing.T) {
	cases := []struct {
		key             string
		typ, name, want string
	}{
		{HelmIndexKey, TypeHelm, "", ""},
		{NpmPackumentKey("lodash"), TypeNpm, "lodash", ""},
		{GomodListKey("example.com/example-corp/widget-sdk"), TypeGomod, "example.com/example-corp/widget-sdk", ""},
		{GomodFileKey("example.com/example-corp/widget-sdk", "@latest"), TypeGomod, "example.com/example-corp/widget-sdk", ""},
		// The sparse index is keyed by the registry path cargo asked for, not
		// by anything a constructor here named.
		{CargoIndexKey("se/rd/serde"), TypeCargo, "", ""},
		{AptKey("dists/noble/InRelease"), TypeApt, "", ""},
	}
	for _, tc := range cases {
		typ, name, version := ParseKey(tc.key)
		if typ != tc.typ || name != tc.name || version != tc.want {
			t.Errorf("ParseKey(%q) = (%q, %q, %q), want (%q, %q, %q)",
				tc.key, typ, name, version, tc.typ, tc.name, tc.want)
		}
	}
}

// A key from outside every tree comes back empty rather than half-derived. The
// caller records the key alone; a type guessed here would put the row under a
// filter that deletes somebody else's digest.
func TestParseKeyRefusesAnUnknownPrefix(t *testing.T) {
	for _, key := range []string{"", "manifests/npm/lodash.json", "scratch/tmp.bin", "index.yaml"} {
		typ, name, version := ParseKey(key)
		if typ != "" || name != "" || version != "" {
			t.Errorf("ParseKey(%q) = (%q, %q, %q), want three empty strings", key, typ, name, version)
		}
	}
}

// Both flat layouts put name and version in one filename with "-" between
// them, and "-" is legal inside both names and inside a prerelease version.
// The rule is the first "-" that opens a digit run ending its segment.
func TestParseKeySplitsFlatFilenamesOnTheVersionRule(t *testing.T) {
	cases := []struct {
		key           string
		name, version string
	}{
		{HelmChartKey("grafana-agent", "0.42.0"), "grafana-agent", "0.42.0"},
		{HelmChartKey("grafana-agent", ""), "grafana-agent", ""},
		{CargoCrateKey("utf8-ranges", "1.0.5"), "utf8-ranges", "1.0.5"},
		// A prerelease carries its own "-", so a rule anchored at the last one
		// splits inside the version and files the row under a name no operator
		// will type.
		{HelmChartKey("cert-manager", "1.14.0-rc.1"), "cert-manager", "1.14.0-rc.1"},
		{CargoCrateKey("serde", "1.0.0-beta.1"), "serde", "1.0.0-beta.1"},
		// md-5 is a published crate. Its trailing digit is not a version
		// because the run does not end the segment.
		{CargoCrateKey("md-5", "0.10.6"), "md-5", "0.10.6"},
		// A "v" prefix is common on chart versions and builder.ParseSemVer
		// keeps it, so a rule that only opens on a digit leaves the whole
		// filename as the chart name and no version at all.
		{HelmChartKey("mychart", "v1.2.3"), "mychart", "v1.2.3"},
		{HelmChartKey("mychart", "V1.2.3"), "mychart", "V1.2.3"},
		{HelmChartKey("mychart", "v1.2.3-rc.1"), "mychart", "v1.2.3-rc.1"},
		// The prefix opens a version only when the digit run is dotted, so a
		// name ending in one stays whole. serde-v8 is a published crate.
		{HelmChartKey("my-v1", ""), "my-v1", ""},
		{CargoCrateKey("serde-v8", "0.1.0"), "serde-v8", "0.1.0"},
	}
	for _, tc := range cases {
		_, name, version := ParseKey(tc.key)
		if name != tc.name || version != tc.version {
			t.Errorf("ParseKey(%q) = (_, %q, %q), want (%q, %q)", tc.key, name, version, tc.name, tc.version)
		}
	}
}

func TestGomodKeysAreTheEscapedModulePath(t *testing.T) {
	for module, want := range map[string]string{
		"github.com/BurntSushi/toml": "gomod/github.com/!burnt!sushi/toml/@v/list",
		"golang.org/x/mod":           "gomod/golang.org/x/mod/@v/list",
		// A manifest named in the escaped form before such names were refused
		// keeps the key its objects were written under.
		"github.com/!burnt!sushi/toml": "gomod/github.com/!burnt!sushi/toml/@v/list",
	} {
		if got := GomodListKey(module); got != want {
			t.Errorf("GomodListKey(%q) = %q, want %q", module, got, want)
		}
	}
}

func TestValidateGomodNameRefusesTheEscapedForm(t *testing.T) {
	if err := ValidateGomodName("github.com/BurntSushi/toml"); err != nil {
		t.Errorf("the go.mod spelling was refused: %v", err)
	}
	err := ValidateGomodName("github.com/!burnt!sushi/toml")
	if err == nil || !strings.Contains(err.Error(), "github.com/BurntSushi/toml") {
		t.Errorf("the escaped form = %v, want a refusal naming github.com/BurntSushi/toml", err)
	}
	if err := ValidateGomodName("github.com/!!x/toml"); err == nil {
		t.Errorf("a name with '!' that does not decode was accepted")
	}
}

func TestParseKeyReadsAGomodKeyBackInGoModSpelling(t *testing.T) {
	typ, name, version := ParseKey(GomodKey("github.com/BurntSushi/toml", "v1.4.0", ".zip"))
	if typ != TypeGomod || name != "github.com/BurntSushi/toml" || version != "v1.4.0" {
		t.Errorf("ParseKey = (%q, %q, %q), want (gomod, github.com/BurntSushi/toml, v1.4.0)", typ, name, version)
	}
}

func TestRubygemsGemIdentity(t *testing.T) {
	for _, tc := range []struct{ file, name, version string }{
		{"rack-3.1.8.gem", "rack", "3.1.8"},
		{"concurrent-ruby-1.3.4.gem", "concurrent-ruby", "1.3.4"},
		{"net-http-persistent-4.0.4.gem", "net-http-persistent", "4.0.4"},
		{"mini_portile2-2.8.7.gem", "mini_portile2", "2.8.7"},
		{"net-http2-0.18.5.gem", "net-http2", "0.18.5"},
		// A name whose own tail is a digit segment: "5" is not the version,
		// because what follows it opens with a digit and no platform does.
		{"md-5-1.0.gem", "md-5", "1.0"},
		{"x25519-1.0.10.gem", "x25519", "1.0.10"},
		{"rails-7.1.0.beta1.gem", "rails", "7.1.0.beta1"},
		{"RedCloth-4.3.4.gem", "RedCloth", "4.3.4"},
		// Platform builds keep the suffix on the version.
		{"nokogiri-1.16.7-x86_64-linux.gem", "nokogiri", "1.16.7-x86_64-linux"},
		{"ffi-1.17.0-x86_64-linux-gnu.gem", "ffi", "1.17.0-x86_64-linux-gnu"},
		{"sass-embedded-1.77.8-arm64-darwin.gem", "sass-embedded", "1.77.8-arm64-darwin"},
		{"jruby-openssl-0.15.0-java.gem", "jruby-openssl", "0.15.0-java"},
		// Not a gem file name.
		{"rack-3.1.8.tgz", "", ""},
		{"rack.gem", "", ""},
		{"-1.0.gem", "", ""},
		{"rack-.gem", "", ""},
		{"rack-1..0.gem", "", ""},
		{"rack-1.0-.gem", "", ""},
	} {
		name, version := RubygemsGemIdentity(tc.file)
		if name != tc.name || version != tc.version {
			t.Errorf("RubygemsGemIdentity(%q) = %q, %q, want %q, %q", tc.file, name, version, tc.name, tc.version)
		}
	}
}

func TestComposerNormalizeVersionFollowsVersionParser(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"v7.1.5":       "7.1.5.0",
		"7.1.5":        "7.1.5.0",
		"7.1.5.0":      "7.1.5.0",
		"V7.1":         "7.1.0.0",
		"7":            "7.0.0.0",
		"2.0.0-RC1":    "2.0.0.0-RC1",
		"v2.0.0-rc1":   "2.0.0.0-RC1",
		"2.0.0-rc.2":   "2.0.0.0-RC2",
		"1.0.0b1":      "1.0.0.0-beta1",
		"1.0.0-alpha":  "1.0.0.0-alpha",
		"1.0.0-a2":     "1.0.0.0-alpha2",
		"1.0.0-pl1":    "1.0.0.0-patch1",
		"1.0.0-stable": "1.0.0.0",
		"1.0.0+build7": "1.0.0.0",
		"1.0.0-dev":    "1.0.0.0-dev",
		"dev-main":     "dev-main",
		"1.x-dev":      "1.x-dev",
		"1.2.3.4.5":    "1.2.3.4.5",
	} {
		if got := ComposerNormalizeVersion(in); got != want {
			t.Errorf("ComposerNormalizeVersion(%q) = %q, want %q", in, got, want)
		}
	}
}
