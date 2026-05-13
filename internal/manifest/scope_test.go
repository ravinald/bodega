package manifest

import (
	"encoding/json"
	"testing"
)

func TestScopeToVersion(t *testing.T) {
	cases := []struct {
		name, key, wantVer, wantRef string
		want                        bool // nil-ness flipped: true = expect non-nil
	}{
		{
			name:    "match by Version",
			key:     "2026.4.0",
			wantVer: "2026.4.0",
			want:    true,
		},
		{
			name:    "match by Ref (git-style)",
			key:     "main",
			wantRef: "main",
			want:    true,
		},
		{"unknown version", "99.99.99", "", "", false},
		{"empty key", "", "", "", false},
	}

	pm := &PackageManifest{
		ConfigVersion: 1,
		Name:          "pkg",
		Type:          TypeNpm,
		Description:   "test",
		Versions: []VersionEntry{
			{Version: "2026.4.0", Hidden: true},
			{Ref: "main"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := pm.ScopeToVersion(tc.key)
			if (got != nil) != tc.want {
				t.Fatalf("got nil=%v, want nil=%v", got == nil, !tc.want)
			}
			if got == nil {
				return
			}
			if got.Name != pm.Name || got.Type != pm.Type || got.Description != pm.Description {
				t.Errorf("top-level fields not preserved: %+v", got)
			}
			if len(got.Versions) != 1 {
				t.Fatalf("versions = %d, want 1", len(got.Versions))
			}
			ve := got.Versions[0]
			if tc.wantVer != "" && ve.Version != tc.wantVer {
				t.Errorf("Version = %q, want %q", ve.Version, tc.wantVer)
			}
			if tc.wantRef != "" && ve.Ref != tc.wantRef {
				t.Errorf("Ref = %q, want %q", ve.Ref, tc.wantRef)
			}
		})
	}
}

func TestScopeToVersionNilReceiver(t *testing.T) {
	var pm *PackageManifest
	if got := pm.ScopeToVersion("1.0.0"); got != nil {
		t.Error("nil receiver should yield nil")
	}
}

// The whole reason ScopeToVersion returns a PackageManifest rather than a
// VersionEntry: the caller writes this as JSON and re-imports it elsewhere.
func TestScopeToVersionRoundTrip(t *testing.T) {
	pm := &PackageManifest{
		ConfigVersion: 1,
		Name:          "@bitwarden/cli",
		Type:          TypeNpm,
		Description:   "Bitwarden CLI",
		DepPolicy:     "direct",
		Versions: []VersionEntry{
			{Version: "2026.3.0", Mode: ModeHosted},
			{Version: "2026.4.0", Mode: ModeHosted, Hidden: true, Frozen: true},
		},
	}

	scoped := pm.ScopeToVersion("2026.4.0")
	if scoped == nil {
		t.Fatal("ScopeToVersion returned nil")
	}

	data, err := json.Marshal(scoped)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var round PackageManifest
	if err := json.Unmarshal(data, &round); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if round.ConfigVersion != 1 || round.Name != pm.Name || round.Type != pm.Type ||
		round.Description != pm.Description || round.DepPolicy != pm.DepPolicy {
		t.Errorf("top-level fields lost: %+v", round)
	}
	if len(round.Versions) != 1 || round.Versions[0].Version != "2026.4.0" {
		t.Errorf("versions = %+v", round.Versions)
	}
	if !round.Versions[0].Hidden || !round.Versions[0].Frozen {
		t.Error("flags lost")
	}
}

// Scoping is pure — callers reuse the source elsewhere in the same request.
func TestScopeToVersionDoesNotMutate(t *testing.T) {
	pm := &PackageManifest{
		Versions: []VersionEntry{
			{Version: "4.17.21"},
			{Version: "4.17.22"},
		},
	}
	_ = pm.ScopeToVersion("4.17.21")
	if len(pm.Versions) != 2 {
		t.Errorf("source mutated: %+v", pm.Versions)
	}
}
