package manifest

import (
	"encoding/json"
	"testing"
)

func TestScopeToVersion_MatchesVersion(t *testing.T) {
	pm := &PackageManifest{
		ConfigVersion: 1,
		Name:          "@bitwarden/cli",
		Type:          TypeNpm,
		Description:   "Bitwarden CLI",
		Versions: []VersionEntry{
			{Version: "2026.3.0"},
			{Version: "2026.4.0", Hidden: true},
		},
	}
	got := pm.ScopeToVersion("2026.4.0")
	if got == nil {
		t.Fatal("expected non-nil result for matching version")
	}
	if got.ConfigVersion != 1 || got.Name != pm.Name || got.Type != pm.Type || got.Description != pm.Description {
		t.Errorf("top-level fields not preserved: %+v", got)
	}
	if len(got.Versions) != 1 || got.Versions[0].Version != "2026.4.0" {
		t.Errorf("scoped versions = %+v, want single 2026.4.0", got.Versions)
	}
}

func TestScopeToVersion_MatchesRef(t *testing.T) {
	pm := &PackageManifest{
		Name: "netbox",
		Type: TypeGit,
		Versions: []VersionEntry{
			{Ref: "v4.5.7"},
			{Ref: "main"},
		},
	}
	got := pm.ScopeToVersion("main")
	if got == nil || len(got.Versions) != 1 || got.Versions[0].Ref != "main" {
		t.Errorf("git Ref match failed: got %+v", got)
	}
}

func TestScopeToVersion_UnknownReturnsNil(t *testing.T) {
	pm := &PackageManifest{
		Name: "lodash",
		Type: TypeNpm,
		Versions: []VersionEntry{
			{Version: "4.17.21"},
		},
	}
	if got := pm.ScopeToVersion("99.99.99"); got != nil {
		t.Errorf("expected nil for unknown version, got %+v", got)
	}
	if got := pm.ScopeToVersion(""); got != nil {
		t.Errorf("empty version must not match anything, got %+v", got)
	}
}

func TestScopeToVersion_NilReceiver(t *testing.T) {
	var pm *PackageManifest
	if got := pm.ScopeToVersion("1.0.0"); got != nil {
		t.Error("nil receiver should yield nil")
	}
}

// TestScopeToVersion_RoundTripsAsJSON is the reason we return a whole
// PackageManifest instead of a bare VersionEntry — the caller expects to
// write this to disk, pipe to `pkg import`, or stuff into an HTTP response
// as a valid manifest.
func TestScopeToVersion_RoundTripsAsJSON(t *testing.T) {
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
		t.Fatalf("marshal scoped: %v", err)
	}

	var round PackageManifest
	if err := json.Unmarshal(data, &round); err != nil {
		t.Fatalf("unmarshal round-trip: %v", err)
	}

	if round.ConfigVersion != 1 || round.Name != pm.Name || round.Type != pm.Type ||
		round.Description != pm.Description || round.DepPolicy != pm.DepPolicy {
		t.Errorf("top-level fields lost in round-trip: %+v", round)
	}
	if len(round.Versions) != 1 || round.Versions[0].Version != "2026.4.0" {
		t.Errorf("versions after round-trip: %+v", round.Versions)
	}
	if !round.Versions[0].Hidden || !round.Versions[0].Frozen {
		t.Error("VersionEntry flags lost in round-trip")
	}
}

// TestScopeToVersion_DoesNotMutateSource makes sure scoping is pure — the
// web UI / CLI reuses the original *PackageManifest elsewhere in the same
// request.
func TestScopeToVersion_DoesNotMutateSource(t *testing.T) {
	pm := &PackageManifest{
		Name: "lodash",
		Type: TypeNpm,
		Versions: []VersionEntry{
			{Version: "4.17.21"},
			{Version: "4.17.22"},
		},
	}
	_ = pm.ScopeToVersion("4.17.21")
	if len(pm.Versions) != 2 {
		t.Errorf("source mutated: versions now %+v", pm.Versions)
	}
}
