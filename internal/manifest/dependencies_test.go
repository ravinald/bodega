package manifest

import (
	"encoding/json"
	"testing"
)

// npmManifestNoDependencies is a per-package manifest written before
// dependencies and artifact_digest existed, in the exact byte shape
// Store.savePackage produces.
const npmManifestNoDependencies = `{
  "config_version": 1,
  "name": "left-pad",
  "type": "npm",
  "versions": [
    {
      "version": "1.3.0",
      "artifact_size": 2478
    }
  ]
}`

// npmManifestWithDependencies is the same package after a fetch on a binary
// that has the fields.
const npmManifestWithDependencies = `{
  "config_version": 1,
  "name": "color-convert",
  "type": "npm",
  "versions": [
    {
      "version": "2.0.1",
      "artifact_size": 6978,
      "dependencies": [
        {
          "name": "color-name",
          "req": "~1.1.4"
        }
      ],
      "artifact_digest": "3dbeb9d4c8d2a5a6b4b0a2c6b7f4e9d18f2c1b3a5e6d7c8b9a0f1e2d3c4b5a69"
    }
  ]
}`

// TestManifestWithoutDependenciesRoundTripsByteIdentically pins the
// migration-free promise. Recording what a version needs must not rewrite
// every manifest on disk: an operator who has not re-fetched should not be
// able to tell the fields exist.
func TestManifestWithoutDependenciesRoundTripsByteIdentically(t *testing.T) {
	var pm PackageManifest
	if err := json.Unmarshal([]byte(npmManifestNoDependencies), &pm); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(pm.Versions[0].Dependencies) != 0 {
		t.Errorf("Dependencies = %v, want none for a manifest that records none", pm.Versions[0].Dependencies)
	}
	if pm.Versions[0].ArtifactDigest != "" {
		t.Errorf("ArtifactDigest = %q, want empty", pm.Versions[0].ArtifactDigest)
	}
	if pm.ConfigVersion != CurrentConfigVersion {
		t.Errorf("ConfigVersion = %d, want %d — neither field may bump it", pm.ConfigVersion, CurrentConfigVersion)
	}

	got, err := json.MarshalIndent(&pm, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(got) != npmManifestNoDependencies {
		t.Errorf("round-trip changed the bytes:\ngot:\n%s\nwant:\n%s", got, npmManifestNoDependencies)
	}
}

// TestManifestWithDependenciesLoadsAndRoundTrips is the other direction: a
// manifest a newer binary wrote, read back. The fields are additive rather
// than a schema version, so a host rolled back to a binary that predates them
// keeps serving the package: it loses the dependency list and the digest, and
// neither decides whether a version resolves.
func TestManifestWithDependenciesLoadsAndRoundTrips(t *testing.T) {
	var pm PackageManifest
	if err := json.Unmarshal([]byte(npmManifestWithDependencies), &pm); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	ve := pm.Versions[0]
	if len(ve.Dependencies) != 1 {
		t.Fatalf("Dependencies = %v, want one entry", ve.Dependencies)
	}
	if ve.Dependencies[0].Name != "color-name" || ve.Dependencies[0].Req != "~1.1.4" {
		t.Errorf("Dependencies[0] = %+v, want color-name ~1.1.4", ve.Dependencies[0])
	}
	if ve.ArtifactDigest == "" {
		t.Error("ArtifactDigest is empty, want the recorded digest")
	}
	if ve.ArtifactSize != 6978 {
		t.Errorf("ArtifactSize = %d, want the neighbouring field to survive the new ones", ve.ArtifactSize)
	}

	got, err := json.MarshalIndent(&pm, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(got) != npmManifestWithDependencies {
		t.Errorf("round-trip changed the bytes:\ngot:\n%s\nwant:\n%s", got, npmManifestWithDependencies)
	}
}

// TestPreDependencyBinaryLoadsAManifestCarryingThem is the rollback direction
// stated as the schema promise it is: a binary without the fields decodes the
// document a binary with them wrote, and every field it does know survives.
// json.Unmarshal ignoring an unknown key is what makes that true, so the test
// decodes into a struct that literally lacks them rather than asserting it.
func TestPreDependencyBinaryLoadsAManifestCarryingThem(t *testing.T) {
	type oldVersionEntry struct {
		Version      string `json:"version,omitempty"`
		ArtifactSize int64  `json:"artifact_size,omitempty"`
	}
	type oldPackageManifest struct {
		ConfigVersion int               `json:"config_version"`
		Name          string            `json:"name"`
		Type          string            `json:"type"`
		Versions      []oldVersionEntry `json:"versions"`
	}

	var old oldPackageManifest
	if err := json.Unmarshal([]byte(npmManifestWithDependencies), &old); err != nil {
		t.Fatalf("a binary predating the fields could not load the manifest: %v", err)
	}
	if old.ConfigVersion != CurrentConfigVersion {
		t.Errorf("ConfigVersion = %d, want %d", old.ConfigVersion, CurrentConfigVersion)
	}
	if len(old.Versions) != 1 || old.Versions[0].Version != "2.0.1" {
		t.Fatalf("versions = %+v, want the one entry intact", old.Versions)
	}
	if old.Versions[0].ArtifactSize != 6978 {
		t.Errorf("artifact_size = %d, want 6978", old.Versions[0].ArtifactSize)
	}
}
