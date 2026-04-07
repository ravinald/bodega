package manifest_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/scaleapi/core-infrastructure/tools/repo-manager/internal/manifest"
)

// writeManifest writes a JSON file and its companion .md5 to dir.
func writeManifest(t *testing.T, dir, name string, v interface{}) {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal %s: %v", name, err)
	}
	data = append(data, '\n')
	path := filepath.Join(dir, name+".json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if err := manifest.WriteMD5File(path, data); err != nil {
		t.Fatalf("write md5 for %s: %v", path, err)
	}
}

func TestLoadAll_HappyPath(t *testing.T) {
	dir := t.TempDir()

	writeManifest(t, dir, "apt", manifest.AptManifest{
		ConfigVersion: 1,
		Entries:       []manifest.AptEntry{{Name: "test-pkg", URL: "https://example.com/repo.git"}},
	})
	writeManifest(t, dir, "git", manifest.GitManifest{
		ConfigVersion: 1,
		Entries:       []manifest.GitEntry{{Name: "myrepo", URL: "https://example.com/repo.git", Ref: "v1.0.0"}},
	})
	writeManifest(t, dir, "pypi", manifest.PypiManifest{
		ConfigVersion:    1,
		BaseRequirements: map[string]string{"myrepo": "v1.0.0"},
		Packages:         []manifest.PypiPackage{{Name: "requests", RequiredBy: []string{"myrepo"}}},
	})
	writeManifest(t, dir, "binary", manifest.BinaryManifest{
		ConfigVersion: 1,
		Entries:       []manifest.BinaryEntry{{Name: "mytool", URL: "https://example.com/mytool.zip"}},
	})

	store, err := manifest.LoadAll(dir)
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}

	if len(store.Apt) != 1 || store.Apt[0].Name != "test-pkg" {
		t.Errorf("apt: expected 1 entry named test-pkg, got %+v", store.Apt)
	}
	if len(store.Git) != 1 || store.Git[0].Ref != "v1.0.0" {
		t.Errorf("git: expected 1 entry at v1.0.0, got %+v", store.Git)
	}
	if len(store.Pypi.Packages) != 1 || store.Pypi.Packages[0].Name != "requests" {
		t.Errorf("pypi: unexpected packages: %+v", store.Pypi.Packages)
	}
	if len(store.Binary) != 1 || store.Binary[0].Name != "mytool" {
		t.Errorf("binary: expected 1 entry named mytool, got %+v", store.Binary)
	}
}

func TestLoadAll_MD5Mismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "git.json")
	data := []byte(`{"config_version":1,"entries":[{"name":"repo","url":"https://x.com","ref":"v1"}]}` + "\n")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	// Write wrong MD5.
	if err := os.WriteFile(path+".md5", []byte("deadbeef\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := manifest.LoadAll(dir)
	if err == nil {
		t.Fatal("expected error on MD5 mismatch, got nil")
	}
}

func TestLoadAll_MissingManifests(t *testing.T) {
	dir := t.TempDir()
	store, err := manifest.LoadAll(dir)
	if err != nil {
		t.Fatalf("LoadAll with empty dir: %v", err)
	}
	if len(store.Apt) != 0 {
		t.Errorf("expected empty apt, got %+v", store.Apt)
	}
}

func TestStore_SaveAndReload(t *testing.T) {
	dir := t.TempDir()

	writeManifest(t, dir, "apt", manifest.AptManifest{ConfigVersion: 1})
	writeManifest(t, dir, "git", manifest.GitManifest{ConfigVersion: 1})
	writeManifest(t, dir, "pypi", manifest.PypiManifest{ConfigVersion: 1})
	writeManifest(t, dir, "binary", manifest.BinaryManifest{ConfigVersion: 1})

	store, err := manifest.LoadAll(dir)
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}

	store.Git = append(store.Git, manifest.GitEntry{Name: "added", URL: "https://x", Ref: "main"})
	if err := store.SaveGit(); err != nil {
		t.Fatalf("SaveGit: %v", err)
	}

	store2, err := manifest.LoadAll(dir)
	if err != nil {
		t.Fatalf("LoadAll after save: %v", err)
	}
	if len(store2.Git) != 1 || store2.Git[0].Name != "added" {
		t.Errorf("expected 1 git entry after reload, got %+v", store2.Git)
	}
}

func TestStore_FrozenEntry(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "git", manifest.GitManifest{
		ConfigVersion: 1,
		Entries:       []manifest.GitEntry{{Name: "repo", URL: "https://x", Ref: "v1"}},
	})
	writeManifest(t, dir, "apt", manifest.AptManifest{ConfigVersion: 1})
	writeManifest(t, dir, "pypi", manifest.PypiManifest{ConfigVersion: 1})
	writeManifest(t, dir, "binary", manifest.BinaryManifest{ConfigVersion: 1})

	store, err := manifest.LoadAll(dir)
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}

	e := store.FindGit("repo")
	if e == nil {
		t.Fatal("git entry not found")
	}
	e.Frozen = true
	if err := store.SaveGit(); err != nil {
		t.Fatal(err)
	}

	store2, err := manifest.LoadAll(dir)
	if err != nil {
		t.Fatalf("LoadAll after save: %v", err)
	}
	if e2 := store2.FindGit("repo"); e2 == nil || !e2.Frozen {
		t.Errorf("frozen flag not persisted: %+v", e2)
	}
}

func TestStore_RemoveGit(t *testing.T) {
	dir := t.TempDir()
	writeManifest(t, dir, "git", manifest.GitManifest{
		ConfigVersion: 1,
		Entries: []manifest.GitEntry{
			{Name: "keep", URL: "https://x", Ref: "v1"},
			{Name: "remove-me", URL: "https://y", Ref: "v2"},
		},
	})
	writeManifest(t, dir, "apt", manifest.AptManifest{ConfigVersion: 1})
	writeManifest(t, dir, "pypi", manifest.PypiManifest{ConfigVersion: 1})
	writeManifest(t, dir, "binary", manifest.BinaryManifest{ConfigVersion: 1})

	store, err := manifest.LoadAll(dir)
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if err := store.RemoveGit("remove-me"); err != nil {
		t.Fatalf("RemoveGit: %v", err)
	}

	store2, err := manifest.LoadAll(dir)
	if err != nil {
		t.Fatalf("LoadAll after remove: %v", err)
	}
	if len(store2.Git) != 1 || store2.Git[0].Name != "keep" {
		t.Errorf("unexpected git entries after remove: %+v", store2.Git)
	}
}
