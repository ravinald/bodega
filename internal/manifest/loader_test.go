package manifest_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ravinald/bodega/internal/manifest"
)

// writePackageManifest writes a PackageManifest as JSON to the expected backend
// path inside dir: {dir}/{type}/{safeName}/manifest.json.
func writePackageManifest(t *testing.T, dir string, pm manifest.PackageManifest) {
	t.Helper()
	pm.ConfigVersion = manifest.CurrentConfigVersion
	data, err := json.MarshalIndent(pm, "", "  ")
	if err != nil {
		t.Fatalf("marshal manifest for %s/%s: %v", pm.Type, pm.Name, err)
	}
	data = append(data, '\n')
	safe := manifest.SafeName(pm.Name)
	path := filepath.Join(dir, pm.Type, safe, "manifest.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// writeIndex writes an Index as index.json to dir.
func writeIndex(t *testing.T, dir string, idx manifest.Index) {
	t.Helper()
	idx.ConfigVersion = manifest.CurrentConfigVersion
	data, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		t.Fatalf("marshal index: %v", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(filepath.Join(dir, "index.json"), data, 0o644); err != nil {
		t.Fatalf("write index.json: %v", err)
	}
}

func TestStore_GetPackage_HappyPath(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	writePackageManifest(t, dir, manifest.PackageManifest{
		Name: "netbox",
		Type: manifest.TypeGit,
		Versions: []manifest.VersionEntry{
			{Ref: "v4.2.0", URL: "https://github.com/netbox-community/netbox"},
		},
	})

	store := manifest.NewLocalStore(dir)
	pm, err := store.GetPackage(ctx, manifest.TypeGit, "netbox")
	if err != nil {
		t.Fatalf("GetPackage: %v", err)
	}
	if pm == nil {
		t.Fatal("expected non-nil PackageManifest")
	}
	if pm.Name != "netbox" {
		t.Errorf("expected name=netbox, got %q", pm.Name)
	}
	if len(pm.Versions) != 1 || pm.Versions[0].Ref != "v4.2.0" {
		t.Errorf("unexpected versions: %+v", pm.Versions)
	}
}

func TestStore_GetPackage_NotFound(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	store := manifest.NewLocalStore(dir)
	pm, err := store.GetPackage(ctx, manifest.TypeGit, "does-not-exist")
	if err != nil {
		t.Fatalf("expected nil error for missing package, got: %v", err)
	}
	if pm != nil {
		t.Errorf("expected nil PackageManifest for missing package, got %+v", pm)
	}
}

func TestStore_SaveAndReload(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	store := manifest.NewLocalStore(dir)

	pm := &manifest.PackageManifest{
		Name: "lodash",
		Type: manifest.TypeNpm,
		Versions: []manifest.VersionEntry{
			{Version: "4.17.21", URL: "https://registry.npmjs.org/lodash"},
		},
	}
	if err := store.SavePackage(ctx, pm); err != nil {
		t.Fatalf("SavePackage: %v", err)
	}

	// Load from a fresh store to verify persistence.
	store2 := manifest.NewLocalStore(dir)
	pm2, err := store2.GetPackage(ctx, manifest.TypeNpm, "lodash")
	if err != nil {
		t.Fatalf("GetPackage after save: %v", err)
	}
	if pm2 == nil {
		t.Fatal("expected non-nil manifest after reload")
	}
	if pm2.ConfigVersion != manifest.CurrentConfigVersion {
		t.Errorf("expected ConfigVersion=%d, got %d", manifest.CurrentConfigVersion, pm2.ConfigVersion)
	}
	if len(pm2.Versions) != 1 || pm2.Versions[0].Version != "4.17.21" {
		t.Errorf("unexpected versions after reload: %+v", pm2.Versions)
	}
}

func TestStore_AddVersion_And_FindVersion(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	store := manifest.NewLocalStore(dir)

	ve := manifest.VersionEntry{
		Version: "2.0.0",
		URL:     "https://example.com/pkg-2.0.0.tar.gz",
	}
	if err := store.AddVersion(ctx, manifest.TypeBinary, "mytool", ve); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}

	got, err := store.FindVersion(ctx, manifest.TypeBinary, "mytool", "2.0.0")
	if err != nil {
		t.Fatalf("FindVersion: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil VersionEntry")
	}
	if got.URL != ve.URL {
		t.Errorf("expected URL=%q, got %q", ve.URL, got.URL)
	}
}

func TestStore_AddVersion_Duplicate(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	store := manifest.NewLocalStore(dir)

	ve := manifest.VersionEntry{Version: "1.0.0"}
	if err := store.AddVersion(ctx, manifest.TypeHelm, "ingress-nginx", ve); err != nil {
		t.Fatalf("first AddVersion: %v", err)
	}
	if err := store.AddVersion(ctx, manifest.TypeHelm, "ingress-nginx", ve); err == nil {
		t.Error("expected error on duplicate AddVersion, got nil")
	}
}

func TestStore_RemoveVersion(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	store := manifest.NewLocalStore(dir)
	if err := store.AddVersion(ctx, manifest.TypeGomod, "github.com/aws/aws-sdk-go-v2", manifest.VersionEntry{Version: "v1.30.0"}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	if err := store.AddVersion(ctx, manifest.TypeGomod, "github.com/aws/aws-sdk-go-v2", manifest.VersionEntry{Version: "v1.31.0"}); err != nil {
		t.Fatalf("AddVersion v1.31.0: %v", err)
	}

	if err := store.RemoveVersion(ctx, manifest.TypeGomod, "github.com/aws/aws-sdk-go-v2", "v1.30.0"); err != nil {
		t.Fatalf("RemoveVersion: %v", err)
	}

	pm, err := store.GetPackage(ctx, manifest.TypeGomod, "github.com/aws/aws-sdk-go-v2")
	if err != nil {
		t.Fatalf("GetPackage: %v", err)
	}
	if len(pm.Versions) != 1 || pm.Versions[0].Version != "v1.31.0" {
		t.Errorf("unexpected versions after remove: %+v", pm.Versions)
	}
}

func TestStore_RemoveVersion_NotFound(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	store := manifest.NewLocalStore(dir)
	if err := store.AddVersion(ctx, manifest.TypeNpm, "react", manifest.VersionEntry{Version: "18.0.0"}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}
	if err := store.RemoveVersion(ctx, manifest.TypeNpm, "react", "99.0.0"); err == nil {
		t.Error("expected error removing non-existent version, got nil")
	}
}

func TestStore_DeletePackage(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	store := manifest.NewLocalStore(dir)
	if err := store.AddVersion(ctx, manifest.TypeApt, "curl", manifest.VersionEntry{Version: "7.88.1"}); err != nil {
		t.Fatalf("AddVersion: %v", err)
	}

	if err := store.DeletePackage(ctx, manifest.TypeApt, "curl"); err != nil {
		t.Fatalf("DeletePackage: %v", err)
	}

	// Fresh store should see the package as absent.
	store2 := manifest.NewLocalStore(dir)
	pm, err := store2.GetPackage(ctx, manifest.TypeApt, "curl")
	if err != nil {
		t.Fatalf("GetPackage after delete: %v", err)
	}
	if pm != nil {
		t.Errorf("expected nil manifest after delete, got %+v", pm)
	}
}

func TestStore_Index_LoadSave(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	writeIndex(t, dir, manifest.Index{
		Packages: map[string][]string{
			manifest.TypeGit: {"netbox", "myrepo"},
			manifest.TypeNpm: {"lodash"},
		},
	})

	store := manifest.NewLocalStore(dir)
	if err := store.LoadIndex(ctx); err != nil {
		t.Fatalf("LoadIndex: %v", err)
	}

	gitPkgs := store.ListPackages(manifest.TypeGit)
	if len(gitPkgs) != 2 {
		t.Errorf("expected 2 git packages, got %v", gitPkgs)
	}

	all := store.AllPackages()
	if len(all[manifest.TypeNpm]) != 1 || all[manifest.TypeNpm][0] != "lodash" {
		t.Errorf("unexpected npm packages: %v", all[manifest.TypeNpm])
	}

	// SavePackage should add a new entry to the index.
	pm := &manifest.PackageManifest{Name: "new-pkg", Type: manifest.TypeBinary}
	if err := store.SavePackage(ctx, pm); err != nil {
		t.Fatalf("SavePackage: %v", err)
	}
	if err := store.SaveIndex(ctx); err != nil {
		t.Fatalf("SaveIndex: %v", err)
	}

	store2 := manifest.NewLocalStore(dir)
	if err := store2.LoadIndex(ctx); err != nil {
		t.Fatalf("LoadIndex on fresh store: %v", err)
	}
	binPkgs := store2.ListPackages(manifest.TypeBinary)
	if len(binPkgs) != 1 || binPkgs[0] != manifest.SafeName("new-pkg") {
		t.Errorf("expected new-pkg in binary index, got %v", binPkgs)
	}
}

func TestStore_Index_Empty(t *testing.T) {
	dir := t.TempDir()
	store := manifest.NewLocalStore(dir)
	// No index loaded — ListPackages should return nil/empty gracefully.
	if got := store.ListPackages(manifest.TypeGit); len(got) != 0 {
		t.Errorf("expected empty slice, got %v", got)
	}
	if got := store.AllPackages(); len(got) != 0 {
		t.Errorf("expected empty map, got %v", got)
	}
}

func TestStore_Graph_AddEdgeAndQuery(t *testing.T) {
	dir := t.TempDir()

	store := manifest.NewLocalStore(dir)

	store.AddEdge(manifest.DepEdge{Parent: "git/netbox", Child: "pypi/django"})
	store.AddEdge(manifest.DepEdge{Parent: "git/netbox", Child: "pypi/requests"})
	store.AddEdge(manifest.DepEdge{Parent: "git/other", Child: "pypi/requests"})

	children := store.ChildrenOf("git/netbox")
	if len(children) != 2 {
		t.Errorf("expected 2 children of git/netbox, got %+v", children)
	}

	parents := store.ParentsOf("pypi/requests")
	if len(parents) != 2 {
		t.Errorf("expected 2 parents of pypi/requests, got %+v", parents)
	}
}

func TestStore_Graph_RemoveEdge(t *testing.T) {
	dir := t.TempDir()

	store := manifest.NewLocalStore(dir)
	store.AddEdge(manifest.DepEdge{Parent: "git/netbox", Child: "pypi/django"})
	store.AddEdge(manifest.DepEdge{Parent: "git/netbox", Child: "pypi/requests"})

	store.RemoveEdge("git/netbox", "pypi/django")

	children := store.ChildrenOf("git/netbox")
	if len(children) != 1 || children[0].Child != "pypi/requests" {
		t.Errorf("unexpected children after remove: %+v", children)
	}
}

func TestStore_Graph_Deduplication(t *testing.T) {
	dir := t.TempDir()

	store := manifest.NewLocalStore(dir)
	e := manifest.DepEdge{Parent: "git/netbox", Child: "pypi/django"}
	store.AddEdge(e)
	store.AddEdge(e)
	store.AddEdge(e)

	if got := store.ChildrenOf("git/netbox"); len(got) != 1 {
		t.Errorf("expected 1 child (deduplication), got %+v", got)
	}
}

func TestStore_Graph_SaveAndLoad(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	store := manifest.NewLocalStore(dir)
	store.AddEdge(manifest.DepEdge{Parent: "git/netbox", Child: "pypi/django"})
	if err := store.SaveGraph(ctx); err != nil {
		t.Fatalf("SaveGraph: %v", err)
	}

	store2 := manifest.NewLocalStore(dir)
	if err := store2.LoadGraph(ctx); err != nil {
		t.Fatalf("LoadGraph: %v", err)
	}
	if got := store2.ChildrenOf("git/netbox"); len(got) != 1 || got[0].Child != "pypi/django" {
		t.Errorf("unexpected edges after reload: %+v", got)
	}
}

func TestStore_Graph_Orphans(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	store := manifest.NewLocalStore(dir)
	// Create "git/myapp" in the store but NOT "pypi/boto3".
	// boto3 is referenced in the graph but has no manifest — it's an orphan.
	_ = store.AddVersion(ctx, "git", "myapp", manifest.VersionEntry{Ref: "main"})
	store.AddEdge(manifest.DepEdge{Parent: "git/myapp", Child: "pypi/boto3"})

	orphans := store.Orphans()
	if len(orphans) != 1 || orphans[0] != "pypi/boto3" {
		t.Errorf("expected [pypi/boto3] as orphan, got %v", orphans)
	}

	// Now add boto3 to the store — no more orphans.
	_ = store.AddVersion(ctx, "pypi", "boto3", manifest.VersionEntry{Version: "1.0"})
	orphans = store.Orphans()
	if len(orphans) != 0 {
		t.Errorf("expected no orphans after adding boto3, got %v", orphans)
	}
}

func TestStore_SafeName_SlashEncoding(t *testing.T) {
	safe := manifest.SafeName("github.com/aws/aws-sdk-go-v2")
	if safe != "github.com--aws--aws-sdk-go-v2" {
		t.Errorf("unexpected SafeName: %q", safe)
	}
}

func TestVersionEntry_VersionedName(t *testing.T) {
	ve := manifest.VersionEntry{Version: "1.2.3"}
	if got := ve.VersionedName("mylib"); got != "mylib@1.2.3" {
		t.Errorf("expected mylib@1.2.3, got %q", got)
	}

	ve2 := manifest.VersionEntry{Ref: "v4.5.6"}
	if got := ve2.VersionedName("myrepo"); got != "myrepo@v4.5.6" {
		t.Errorf("expected myrepo@v4.5.6, got %q", got)
	}

	ve3 := manifest.VersionEntry{}
	if got := ve3.VersionedName("unnamed"); got != "unnamed" {
		t.Errorf("expected unnamed, got %q", got)
	}
}

func TestVersionEntry_IsRelease(t *testing.T) {
	cases := []struct {
		ve   manifest.VersionEntry
		want bool
	}{
		{manifest.VersionEntry{Source: "release"}, true},
		{manifest.VersionEntry{Source: "clone"}, false},
		{manifest.VersionEntry{Ref: "v1.2.3"}, true},
		{manifest.VersionEntry{Ref: "1.0.0"}, true},
		{manifest.VersionEntry{Ref: "main"}, false},
		{manifest.VersionEntry{Ref: "develop"}, false},
		{manifest.VersionEntry{}, false},
	}
	for _, tc := range cases {
		if got := tc.ve.IsRelease(); got != tc.want {
			t.Errorf("IsRelease(%+v) = %v, want %v", tc.ve, got, tc.want)
		}
	}
}

func TestVersionEntry_EffectiveMode(t *testing.T) {
	ve := manifest.VersionEntry{}
	if got := ve.EffectiveMode(); got != manifest.ModeHosted {
		t.Errorf("expected ModeHosted default, got %q", got)
	}
	ve.Mode = manifest.ModeProxy
	if got := ve.EffectiveMode(); got != manifest.ModeProxy {
		t.Errorf("expected ModeProxy, got %q", got)
	}
}
