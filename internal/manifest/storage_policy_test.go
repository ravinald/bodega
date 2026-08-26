package manifest

import (
	"encoding/json"
	"testing"
)

// gitManifestNoStoragePolicy is a per-package manifest written before
// storage_policy existed, in the exact byte shape Store.savePackage produces.
const gitManifestNoStoragePolicy = `{
  "config_version": 1,
  "name": "netbox",
  "type": "git",
  "versions": [
    {
      "ref": "v4.5.5",
      "source": "release"
    }
  ]
}`

// TestManifestWithoutStoragePolicyRoundTripsByteIdentically pins the
// migration-free promise. Adding a placement knob must not rewrite every
// manifest on disk: an operator who never sets it should not be able to tell
// the field exists.
func TestManifestWithoutStoragePolicyRoundTripsByteIdentically(t *testing.T) {
	var pm PackageManifest
	if err := json.Unmarshal([]byte(gitManifestNoStoragePolicy), &pm); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if pm.StoragePolicy != "" {
		t.Errorf("StoragePolicy = %q, want empty for a manifest that names none", pm.StoragePolicy)
	}
	if pm.ConfigVersion != CurrentConfigVersion {
		t.Errorf("ConfigVersion = %d, want %d — storage_policy must not bump it",
			pm.ConfigVersion, CurrentConfigVersion)
	}

	got, err := json.MarshalIndent(&pm, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(got) != gitManifestNoStoragePolicy {
		t.Errorf("round-trip changed the bytes:\ngot:\n%s\nwant:\n%s", got, gitManifestNoStoragePolicy)
	}
}

// TestStoragePolicyIsSeparateFromVersionStorage guards the naming decision.
// PackageManifest.StoragePolicy is future tense ("put new versions here");
// VersionEntry.Storage is past tense ("this version's bytes are here"). They
// must never collapse into one JSON key, or a reader of a manifest cannot tell
// a rule from a record.
func TestStoragePolicyIsSeparateFromVersionStorage(t *testing.T) {
	pm := PackageManifest{
		ConfigVersion: CurrentConfigVersion,
		Name:          "netbox",
		Type:          TypeGit,
		StoragePolicy: "archive",
		Versions:      []VersionEntry{{Ref: "v4.5.5", Storage: "bulk"}},
	}
	data, err := json.Marshal(&pm)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var back PackageManifest
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.StoragePolicy != "archive" {
		t.Errorf(`storage_policy = %q, want "archive"`, back.StoragePolicy)
	}
	if back.Versions[0].Storage != "bulk" {
		t.Errorf(`versions[0].storage = %q, want "bulk" — the package rule overwrote the version's record`,
			back.Versions[0].Storage)
	}
}
