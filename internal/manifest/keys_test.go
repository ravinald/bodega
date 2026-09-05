package manifest

import "testing"

// roundTrip is one type's constructor output and the identity ParseKey must
// read back out of it.
type roundTrip struct {
	key     string
	name    string
	version string
}

// keyRoundTrips holds one case per member of AllTypes, built by the
// constructor rather than by a hand-written string: a key literal would keep
// passing after the constructor changed the layout underneath it.
//
// pypi is the one entry with no constructor. Wheels upload as a directory and
// ArtifactKeys answers ErrPypiNoObjectKey for them, so the key here is built
// from PypiWheelPrefix the way the sync writes it.
var keyRoundTrips = map[string]roundTrip{
	TypeBinary: {
		key:     BinaryKey("aws-cli", "2.15.0", "awscliv2.zip"),
		name:    "aws-cli",
		version: "2.15.0",
	},
	TypeGit: {
		key:     GitKey("github.com/ravinald/bodega", "v1.2.0", false),
		name:    "github.com/ravinald/bodega",
		version: "v1.2.0",
	},
	TypeApt: {
		key:     AptKey("pool/main/n/nginx/nginx_1.24.0-2ubuntu7.1_amd64.deb"),
		name:    "nginx",
		version: "1.24.0-2ubuntu7.1",
	},
	TypePypi: {
		key:     PypiWheelPrefix + "1.26.0/boto3-1.26.0-py3-none-any.whl",
		name:    "boto3",
		version: "1.26.0",
	},
	TypeGomod: {
		key:     GomodKey("github.com/aws/aws-sdk-go-v2", "v1.30.0", ".zip"),
		name:    "github.com/aws/aws-sdk-go-v2",
		version: "v1.30.0",
	},
	TypeHelm: {
		key:     HelmChartKey("ingress-nginx", "4.11.2"),
		name:    "ingress-nginx",
		version: "4.11.2",
	},
	TypeNpm: {
		key:     NpmTarballKey("@bitwarden/cli", "2024.7.2"),
		name:    "@bitwarden/cli",
		version: "2024.7.2",
	},
	TypeCargo: {
		key:     CargoCrateKey("serde", "1.0.210"),
		name:    "serde",
		version: "1.0.210",
	},
}

// TestParseKeyRoundTripsEveryType is the guard on the pair. A ninth type added
// with a constructor and no ParseKey arm fails here rather than in production,
// where it costs every artifact of that type its package identity and
// `bodega pkg checksum clear` its only filter.
func TestParseKeyRoundTripsEveryType(t *testing.T) {
	for _, typ := range AllTypes {
		want, ok := keyRoundTrips[typ]
		if !ok {
			t.Errorf("type %q is in AllTypes with no round-trip case: build its key with the constructor and add the ParseKey arm that reads it back", typ)
			continue
		}
		gotType, gotName, gotVersion := ParseKey(want.key)
		if gotType != typ || gotName != want.name || gotVersion != want.version {
			t.Errorf("ParseKey(%q) = (%q, %q, %q), want (%q, %q, %q)",
				want.key, gotType, gotName, gotVersion, typ, want.name, want.version)
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
		{GomodListKey("github.com/aws/aws-sdk-go-v2"), TypeGomod, "github.com/aws/aws-sdk-go-v2", ""},
		{GomodFileKey("github.com/aws/aws-sdk-go-v2", "@latest"), TypeGomod, "github.com/aws/aws-sdk-go-v2", ""},
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
// them, and "-" is legal inside both names. The rule is the last "-" whose
// remainder opens with a digit, which is what an unversioned chart depends on.
func TestParseKeySplitsFlatFilenamesOnTheVersionRule(t *testing.T) {
	cases := []struct {
		key           string
		name, version string
	}{
		{HelmChartKey("grafana-agent", "0.42.0"), "grafana-agent", "0.42.0"},
		{HelmChartKey("grafana-agent", ""), "grafana-agent", ""},
		{CargoCrateKey("utf8-ranges", "1.0.5"), "utf8-ranges", "1.0.5"},
	}
	for _, tc := range cases {
		_, name, version := ParseKey(tc.key)
		if name != tc.name || version != tc.version {
			t.Errorf("ParseKey(%q) = (_, %q, %q), want (%q, %q)", tc.key, name, version, tc.name, tc.version)
		}
	}
}
