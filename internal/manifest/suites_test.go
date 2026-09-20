package manifest

import (
	"encoding/json"
	"testing"
)

// aptManifestNoSuites is a per-package manifest written before the suites
// field existed, in the exact byte shape Store.savePackage produces.
const aptManifestNoSuites = `{
  "config_version": 1,
  "name": "hello",
  "type": "apt",
  "description": "example package",
  "versions": [
    {
      "version": "2.10-3build1",
      "source_name": "hello",
      "metadata": {
        "Architecture": "amd64"
      }
    }
  ]
}`

// TestManifestWithoutSuitesRoundTripsByteIdentically pins the migration-free
// promise of the suites field: omitempty on a nil slice means a manifest that
// predates it is rewritten unchanged, so config_version stays at 1.
func TestManifestWithoutSuitesRoundTripsByteIdentically(t *testing.T) {
	var pm PackageManifest
	if err := json.Unmarshal([]byte(aptManifestNoSuites), &pm); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if pm.ConfigVersion != CurrentConfigVersion {
		t.Errorf("ConfigVersion = %d, want %d — the suites field must not bump it", pm.ConfigVersion, CurrentConfigVersion)
	}
	if pm.Versions[0].Suites != nil {
		t.Errorf("Suites = %#v, want nil for a manifest that names none", pm.Versions[0].Suites)
	}

	got, err := json.MarshalIndent(&pm, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(got) != aptManifestNoSuites {
		t.Errorf("round-trip changed the bytes:\ngot:\n%s\nwant:\n%s", got, aptManifestNoSuites)
	}
}

func TestEffectiveSuitesAndInSuite(t *testing.T) {
	cases := []struct {
		name   string
		suites []string
		def    string
		want   []string
		in     map[string]bool
	}{
		{
			name: "no suites falls back to the default",
			def:  "noble",
			want: []string{"noble"},
			in:   map[string]bool{"noble": true, "jammy": false},
		},
		{
			name:   "explicit suites ignore the default",
			suites: []string{"jammy"},
			def:    "noble",
			want:   []string{"jammy"},
			in:     map[string]bool{"noble": false, "jammy": true},
		},
		{
			name:   "an entry can be in several suites at once",
			suites: []string{"noble", "jammy"},
			def:    "noble",
			want:   []string{"noble", "jammy"},
			in:     map[string]bool{"noble": true, "jammy": true, "bookworm": false},
		},
		{
			name: "no suites and no default belongs nowhere",
			want: nil,
			in:   map[string]bool{"": false, "noble": false},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ve := VersionEntry{Suites: tc.suites}
			got := ve.EffectiveSuites(tc.def)
			if len(got) != len(tc.want) {
				t.Fatalf("EffectiveSuites(%q) = %v, want %v", tc.def, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("EffectiveSuites(%q) = %v, want %v", tc.def, got, tc.want)
				}
			}
			for suite, want := range tc.in {
				if in := ve.InSuite(suite, tc.def); in != want {
					t.Errorf("InSuite(%q, %q) = %v, want %v", suite, tc.def, in, want)
				}
			}
		})
	}
}
