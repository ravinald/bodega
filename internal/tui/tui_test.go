package tui

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/ravinald/bodega/internal/aptsources"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/inventory"
	"github.com/ravinald/bodega/internal/manifest"
)

// --- splitArgs ---

func TestSplitArgs(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"", nil},
		{"build apt", []string{"build", "apt"}},
		{"delete apt/amazon-efs-utils", []string{"delete", "apt/amazon-efs-utils"}},
		{`create git --name "my repo"`, []string{"create", "git", "--name", "my repo"}},
		{"  status  ", []string{"status"}},
		{"build git pypi", []string{"build", "git", "pypi"}},
		{"freeze binary/awscli-v2", []string{"freeze", "binary/awscli-v2"}},
	}

	for _, tt := range tests {
		got := splitArgs(tt.input)
		if len(got) != len(tt.want) {
			t.Errorf("splitArgs(%q) len=%d want %d: got %v", tt.input, len(got), len(tt.want), got)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("splitArgs(%q)[%d] = %q want %q", tt.input, i, got[i], tt.want[i])
			}
		}
	}
}

// --- extractFlag ---

func TestExtractFlag(t *testing.T) {
	args := []string{"git", "--entry", "netbox", "pypi"}
	val, remaining := extractFlag(args, "--entry")
	if val != "netbox" {
		t.Errorf("value = %q, want netbox", val)
	}
	if len(remaining) != 2 || remaining[0] != "git" || remaining[1] != "pypi" {
		t.Errorf("remaining = %v, want [git pypi]", remaining)
	}
}

func TestExtractFlagAbsent(t *testing.T) {
	args := []string{"git", "pypi"}
	val, remaining := extractFlag(args, "--entry")
	if val != "" {
		t.Errorf("absent flag: value = %q, want empty", val)
	}
	if len(remaining) != 2 {
		t.Errorf("absent flag: remaining = %v, want original", remaining)
	}
}

// --- isValidType ---

func TestIsValidType(t *testing.T) {
	for _, valid := range []string{"apt", "git", "pypi", "binary"} {
		if !isValidType(valid) {
			t.Errorf("isValidType(%q) = false, want true", valid)
		}
	}
	for _, invalid := range []string{"", "snap", "docker", "APT"} {
		if isValidType(invalid) {
			t.Errorf("isValidType(%q) = true, want false", invalid)
		}
	}
}

// --- resolveTypes ---

func TestResolveTypesEmpty(t *testing.T) {
	types, err := resolveTypes(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(types) != len(manifest.AllTypes) {
		t.Errorf("len = %d, want %d", len(types), len(manifest.AllTypes))
	}
}

func TestResolveTypesInvalid(t *testing.T) {
	_, err := resolveTypes([]string{"unknown"})
	if err == nil {
		t.Error("expected error for unknown type")
	}
}

// --- BuildTree ---

func TestBuildTree(t *testing.T) {
	store := manifest.NewLocalStore(t.TempDir())
	ctx := t.Context()
	_ = store.AddVersion(ctx, manifest.TypeApt, "pkg-a", manifest.VersionEntry{Version: "1.0"})
	_ = store.AddVersion(ctx, manifest.TypeGit, "repo-b", manifest.VersionEntry{Ref: "v2.0", URL: "https://example.com/b.git"})
	_ = store.AddVersion(ctx, manifest.TypePypi, "requests", manifest.VersionEntry{Version: "2.28.0"})
	_ = store.AddVersion(ctx, manifest.TypeBinary, "tool-c", manifest.VersionEntry{URL: "https://example.com/tool-c"})

	statuses := []inventory.EntryStatus{
		{Type: manifest.TypeApt, Name: "pkg-a@1.0", Present: true},
		{Type: manifest.TypeGit, Name: "repo-b@main", Present: false},
		{Type: manifest.TypePypi, Name: "wheels", Present: true},
		{Type: manifest.TypeBinary, Name: "tool-c", Present: false},
	}

	roots := BuildTree(store, statuses)

	if len(roots) != 7 {
		t.Fatalf("expected 7 root groups, got %d", len(roots))
	}

	// apt group — children are now package sub-groups
	aptGroup := roots[0]
	if !aptGroup.IsGroup || aptGroup.EntryType != manifest.TypeApt {
		t.Errorf("roots[0] not apt group: %+v", aptGroup)
	}
	if len(aptGroup.Children) != 1 {
		t.Fatalf("apt package groups = %d, want 1", len(aptGroup.Children))
	}
	aptPkg := aptGroup.Children[0]
	if !aptPkg.IsGroup || aptPkg.Label != "pkg-a" {
		t.Errorf("apt pkg group label = %q, want pkg-a", aptPkg.Label)
	}
	if len(aptPkg.Children) != 1 {
		t.Fatalf("apt pkg-a versions = %d, want 1", len(aptPkg.Children))
	}
	if !aptPkg.Children[0].InS3 {
		t.Error("pkg-a@1.0: InS3 should be true")
	}

	// git group
	gitGroup := roots[1]
	if len(gitGroup.Children) != 1 {
		t.Fatalf("git package groups = %d, want 1", len(gitGroup.Children))
	}
	gitPkg := gitGroup.Children[0]
	if len(gitPkg.Children) != 1 {
		t.Fatalf("git repo-b versions = %d, want 1", len(gitPkg.Children))
	}
	if gitPkg.Children[0].InS3 {
		t.Error("repo-b@main: InS3 should be false")
	}

	// pypi group
	pypiGroup := roots[2]
	if len(pypiGroup.Children) != 1 {
		t.Fatalf("pypi package groups = %d, want 1", len(pypiGroup.Children))
	}
	pypiPkg := pypiGroup.Children[0]
	if len(pypiPkg.Children) != 1 {
		t.Fatalf("pypi pkg versions = %d, want 1", len(pypiPkg.Children))
	}
	if !pypiPkg.Children[0].InS3 {
		t.Error("pypi pkg: InS3 should be true")
	}
}

// Guards the edit-flow invariant: leaf nodes carry a raw Version that
// ScopeToVersion can match, package headers carry a Name.
func TestBuildTreeLeafMetadata(t *testing.T) {
	store := manifest.NewLocalStore(t.TempDir())
	ctx := t.Context()
	_ = store.AddVersion(ctx, manifest.TypeNpm, "@scope/pkg", manifest.VersionEntry{Version: "1.0.0"})
	_ = store.AddVersion(ctx, manifest.TypeNpm, "@scope/pkg", manifest.VersionEntry{Version: "2.0.0", Hidden: true})
	_ = store.AddVersion(ctx, manifest.TypeGit, "repo", manifest.VersionEntry{Ref: "main", URL: "https://example.com/r.git"})

	roots := BuildTree(store, nil)

	// Find npm group, then @scope/pkg package header.
	var npmPkg *TreeNode
	for i, g := range roots {
		if g.EntryType != manifest.TypeNpm {
			continue
		}
		for j := range roots[i].Children {
			child := &roots[i].Children[j]
			if child.Name == "@scope/pkg" {
				npmPkg = child
				break
			}
		}
	}
	if npmPkg == nil {
		t.Fatal("@scope/pkg package header not found under npm")
	}
	if !npmPkg.IsGroup || npmPkg.Name == "" {
		t.Errorf("package header should be IsGroup=true and Name set, got %+v", npmPkg)
	}
	if npmPkg.Version != "" {
		t.Errorf("package header should have empty Version, got %q", npmPkg.Version)
	}
	if len(npmPkg.Children) != 2 {
		t.Fatalf("@scope/pkg should have 2 version children, got %d", len(npmPkg.Children))
	}
	var gotVersions []string
	for _, c := range npmPkg.Children {
		gotVersions = append(gotVersions, c.Version)
		if c.Name != "@scope/pkg" {
			t.Errorf("version leaf Name = %q, want @scope/pkg", c.Name)
		}
		if c.IsGroup {
			t.Errorf("version leaf should not be IsGroup: %+v", c)
		}
	}
	// Exact version strings must match what ScopeToVersion compares against.
	if !contains(gotVersions, "1.0.0") || !contains(gotVersions, "2.0.0") {
		t.Errorf("version leaves = %v, want both 1.0.0 and 2.0.0", gotVersions)
	}

	// Verify the hidden flag made it onto the leaf.
	for _, c := range npmPkg.Children {
		if c.Version == "2.0.0" && !c.Hidden {
			t.Error("2.0.0 leaf should have Hidden=true")
		}
		if c.Version == "1.0.0" && c.Hidden {
			t.Error("1.0.0 leaf should have Hidden=false")
		}
	}

	// Git: Ref is what ScopeToVersion matches against. Leaf Version must be the Ref.
	var gitLeaf *TreeNode
	for i, g := range roots {
		if g.EntryType != manifest.TypeGit {
			continue
		}
		for j := range roots[i].Children {
			pkg := &roots[i].Children[j]
			if pkg.Name == "repo" && len(pkg.Children) > 0 {
				gitLeaf = &pkg.Children[0]
			}
		}
	}
	if gitLeaf == nil {
		t.Fatal("git repo leaf not found")
	}
	if gitLeaf.Version != "main" {
		t.Errorf("git leaf Version = %q, want main (Ref fallback)", gitLeaf.Version)
	}
}

func contains(ss []string, s string) bool {
	for _, v := range ss {
		if v == s {
			return true
		}
	}
	return false
}

// TestMakeEditSave_FullManifest covers the happy path for editing the full
// PackageManifest via the TUI save closure. The closure should parse the
// buffer, replace the stored manifest, and persist.
func TestMakeEditSave_FullManifest(t *testing.T) {
	store := manifest.NewLocalStore(t.TempDir())
	ctx := t.Context()
	_ = store.AddVersion(ctx, manifest.TypeNpm, "lodash", manifest.VersionEntry{Version: "4.17.20"})

	m := &appModel{store: store, log: &logPaneModel{}}
	save := m.makeEditSave(manifest.TypeNpm, "lodash", "") // full-manifest edit

	edited := `{
		"config_version": 1,
		"name": "lodash",
		"type": "npm",
		"description": "edited via TUI",
		"versions": [
			{"version": "4.17.20"},
			{"version": "4.17.21", "frozen": true}
		]
	}`
	if err := save([]byte(edited)); err != nil {
		t.Fatalf("save: %v", err)
	}

	pm, _ := store.GetPackage(context.Background(), manifest.TypeNpm, "lodash")
	if pm == nil {
		t.Fatal("lodash disappeared after save")
	}
	if pm.Description != "edited via TUI" {
		t.Errorf("description = %q, want 'edited via TUI'", pm.Description)
	}
	if len(pm.Versions) != 2 {
		t.Errorf("versions count = %d, want 2", len(pm.Versions))
	}
}

// TestMakeEditSave_VersionScoped covers the version-scoped edit path: buffer
// is a one-entry PackageManifest, save merges that entry back into the
// existing pm in place, preserving other versions.
func TestMakeEditSave_VersionScoped(t *testing.T) {
	store := manifest.NewLocalStore(t.TempDir())
	ctx := t.Context()
	_ = store.AddVersion(ctx, manifest.TypeNpm, "@scope/pkg", manifest.VersionEntry{Version: "1.0.0"})
	_ = store.AddVersion(ctx, manifest.TypeNpm, "@scope/pkg", manifest.VersionEntry{Version: "2.0.0"})

	m := &appModel{store: store, log: &logPaneModel{}}
	save := m.makeEditSave(manifest.TypeNpm, "@scope/pkg", "2.0.0")

	edited := `{
		"config_version": 1,
		"name": "@scope/pkg",
		"type": "npm",
		"versions": [
			{"version": "2.0.0", "hidden": true, "frozen": true, "description": "quarantined"}
		]
	}`
	if err := save([]byte(edited)); err != nil {
		t.Fatalf("save: %v", err)
	}

	pm, _ := store.GetPackage(context.Background(), manifest.TypeNpm, "@scope/pkg")
	if pm == nil || len(pm.Versions) != 2 {
		t.Fatalf("expected 2 versions after scoped edit, got pm=%+v", pm)
	}
	// 1.0.0 must remain untouched; 2.0.0 must have the new flags.
	var v1, v2 *manifest.VersionEntry
	for i := range pm.Versions {
		if pm.Versions[i].Version == "1.0.0" {
			v1 = &pm.Versions[i]
		}
		if pm.Versions[i].Version == "2.0.0" {
			v2 = &pm.Versions[i]
		}
	}
	if v1 == nil || v1.Hidden || v1.Frozen {
		t.Errorf("1.0.0 should be unchanged, got %+v", v1)
	}
	if v2 == nil || !v2.Hidden || !v2.Frozen || v2.Description != "quarantined" {
		t.Errorf("2.0.0 should be hidden+frozen with description, got %+v", v2)
	}
}

// TestMakeEditSave_RejectsRename: full-manifest edits must not change Name
// or Type — renames are a different operation.
func TestMakeEditSave_RejectsRename(t *testing.T) {
	store := manifest.NewLocalStore(t.TempDir())
	ctx := t.Context()
	_ = store.AddVersion(ctx, manifest.TypeNpm, "lodash", manifest.VersionEntry{Version: "4.17.20"})

	m := &appModel{store: store, log: &logPaneModel{}}
	save := m.makeEditSave(manifest.TypeNpm, "lodash", "")

	rename := `{"config_version": 1, "name": "lodash-renamed", "type": "npm", "versions":[{"version":"4.17.20"}]}`
	err := save([]byte(rename))
	if err == nil {
		t.Fatal("expected error on rename, got nil")
	}
	if !strings.Contains(err.Error(), "cannot change Name") {
		t.Errorf("error = %q, want message about Name change", err.Error())
	}
}

// TestMakeEditSave_RejectsUnknownVersion: if the user points the TUI at a
// version that's been deleted out from under them (race), the scoped save
// reports a clean error instead of blindly mutating an unrelated slot.
func TestMakeEditSave_RejectsUnknownVersion(t *testing.T) {
	store := manifest.NewLocalStore(t.TempDir())
	ctx := t.Context()
	_ = store.AddVersion(ctx, manifest.TypeNpm, "pkg", manifest.VersionEntry{Version: "1.0.0"})

	m := &appModel{store: store, log: &logPaneModel{}}
	save := m.makeEditSave(manifest.TypeNpm, "pkg", "9.9.9") // not in store

	edited := `{"config_version":1,"name":"pkg","type":"npm","versions":[{"version":"9.9.9"}]}`
	err := save([]byte(edited))
	if err == nil {
		t.Fatal("expected error on unknown version, got nil")
	}
	if !strings.Contains(err.Error(), "no longer present") {
		t.Errorf("error = %q, want 'no longer present'", err.Error())
	}
}

// TestMakeEditSave_RejectsInvalidJSON: malformed buffer surfaces a parse
// error without persisting anything.
func TestMakeEditSave_RejectsInvalidJSON(t *testing.T) {
	store := manifest.NewLocalStore(t.TempDir())
	ctx := t.Context()
	_ = store.AddVersion(ctx, manifest.TypeNpm, "pkg", manifest.VersionEntry{Version: "1.0.0"})

	m := &appModel{store: store, log: &logPaneModel{}}
	save := m.makeEditSave(manifest.TypeNpm, "pkg", "")

	if err := save([]byte("{not json")); err == nil {
		t.Error("expected parse error")
	}
	// Original manifest must not have been mutated.
	pm, _ := store.GetPackage(context.Background(), manifest.TypeNpm, "pkg")
	if pm == nil || len(pm.Versions) != 1 || pm.Versions[0].Version != "1.0.0" {
		b, _ := json.MarshalIndent(pm, "", "  ")
		t.Errorf("manifest should be untouched after parse failure; got %s", b)
	}
}

// --- sourcesModel navigation ---

func TestSourcesModelNavigation(t *testing.T) {
	store := manifest.NewLocalStore(t.TempDir())
	ctx := t.Context()
	_ = store.AddVersion(ctx, manifest.TypeApt, "pkg-a", manifest.VersionEntry{Version: "1.0"})
	_ = store.AddVersion(ctx, manifest.TypeApt, "pkg-b", manifest.VersionEntry{Version: "1.0"})
	roots := BuildTree(store, nil)
	m := newSourcesModel(roots)

	// Initial cursor is on first row (apt/ group header).
	if m.cursor != 0 {
		t.Errorf("initial cursor = %d, want 0", m.cursor)
	}

	m.CursorDown()
	if m.cursor != 1 {
		t.Errorf("after CursorDown cursor = %d, want 1", m.cursor)
	}

	// CursorUp back to group header.
	m.CursorUp()
	if m.cursor != 0 {
		t.Errorf("after CursorUp cursor = %d, want 0", m.cursor)
	}

	// CursorUp at top should be a no-op.
	m.CursorUp()
	if m.cursor != 0 {
		t.Errorf("CursorUp at top changed cursor to %d", m.cursor)
	}
}

// --- ToggleExpand ---

func TestToggleExpand(t *testing.T) {
	store := manifest.NewLocalStore(t.TempDir())
	ctx := t.Context()
	_ = store.AddVersion(ctx, manifest.TypeApt, "pkg-a", manifest.VersionEntry{Version: "1.0"})
	roots := BuildTree(store, nil)
	m := newSourcesModel(roots)

	// Initially all groups are collapsed. Row 0 = apt/ group.
	collapsedLen := len(m.flatList)
	m.cursor = 0

	// Expand the apt group.
	m.ToggleExpand()
	expandedLen := len(m.flatList)
	if expandedLen <= collapsedLen {
		t.Fatalf("after expand flatList len = %d, expected more than %d", expandedLen, collapsedLen)
	}

	// Collapse it again.
	m.ToggleExpand()
	if len(m.flatList) != collapsedLen {
		t.Errorf("after re-collapse flatList len = %d, expected %d", len(m.flatList), collapsedLen)
	}

	// Re-expand to verify round-trip.
	m.ToggleExpand()
	if len(m.flatList) != expandedLen {
		t.Errorf("after re-expand flatList len = %d, want %d", len(m.flatList), expandedLen)
	}
}

// --- popupModel ---

func TestPopupDismiss(t *testing.T) {
	p := popupModel{kind: popupHelp}
	if !p.Active() {
		t.Error("expected popup active")
	}
	p.dismiss()
	if p.Active() {
		t.Error("expected popup inactive after dismiss")
	}
}

func TestPopupConfirm(t *testing.T) {
	called := false
	p := popupModel{
		kind:  popupConfirm,
		onYes: func() { called = true },
	}
	p.confirm()
	if !called {
		t.Error("onYes was not called")
	}
	if p.Active() {
		t.Error("popup should be inactive after confirm")
	}
}

// --- details rendering smoke test ---

func TestDetailsViewNoNode(t *testing.T) {
	store := manifest.NewLocalStore(t.TempDir())
	d := newDetailsModel(store, &config.Config{})
	v := d.View()
	if v == "" {
		t.Error("details view returned empty string when no node selected")
	}
}

func TestDetailsViewAptEntry(t *testing.T) {
	store := manifest.NewLocalStore(t.TempDir())
	ctx := t.Context()
	_ = store.AddVersion(ctx, manifest.TypeApt, "pkg-a", manifest.VersionEntry{Version: "1.0", URL: "https://example.com/pkg-a"})
	d := newDetailsModel(store, &config.Config{})
	d.width = 80
	d.SetNode(&TreeNode{
		EntryType: manifest.TypeApt,
		Name:      "pkg-a",
		InS3:      true,
	})
	v := d.View()
	if v == "" {
		t.Error("details view returned empty string for apt entry")
	}
}

// Details-pane JSON should scope to the selected version's single VersionEntry
// when a leaf is cursored, and show the full manifest on the package header.
// Regression guard: this diverged from the edit popup in an earlier release.
func TestDetailsRawJSONScoping(t *testing.T) {
	store := manifest.NewLocalStore(t.TempDir())
	ctx := t.Context()
	_ = store.AddVersion(ctx, manifest.TypeNpm, "pkg", manifest.VersionEntry{Version: "1.0.0"})
	_ = store.AddVersion(ctx, manifest.TypeNpm, "pkg", manifest.VersionEntry{Version: "2.0.0"})

	d := newDetailsModel(store, &config.Config{})

	leaf := d.rawJSON(&TreeNode{EntryType: manifest.TypeNpm, Name: "pkg", Version: "2.0.0"})
	if leaf == "" {
		t.Fatal("leaf JSON empty")
	}
	if strings.Contains(leaf, `"1.0.0"`) {
		t.Errorf("version-leaf details should NOT contain 1.0.0:\n%s", leaf)
	}
	if !strings.Contains(leaf, `"2.0.0"`) {
		t.Errorf("version-leaf details should contain 2.0.0:\n%s", leaf)
	}

	header := d.rawJSON(&TreeNode{EntryType: manifest.TypeNpm, Name: "pkg"})
	if !strings.Contains(header, `"1.0.0"`) || !strings.Contains(header, `"2.0.0"`) {
		t.Errorf("package-header details should contain both versions:\n%s", header)
	}
}

// Guards that the displayed object key matches where the uploader actually
// writes: safe-encoded (/ → --) for scoped npm and git, and the module path
// with its slashes intact for gomod, which is the form a Go client requests.
func TestS3PathSafeEncoding(t *testing.T) {
	store := manifest.NewLocalStore(t.TempDir())
	ctx := t.Context()
	_ = store.AddVersion(ctx, manifest.TypeNpm, "@bitwarden/cli", manifest.VersionEntry{Version: "2026.3.0"})
	_ = store.AddVersion(ctx, manifest.TypeGomod, "github.com/aws/aws-sdk-go", manifest.VersionEntry{Version: "v1.2.3"})
	_ = store.AddVersion(ctx, manifest.TypeGit, "netbox-community/netbox", manifest.VersionEntry{Ref: "v4.5.7"})

	cases := []struct {
		label, typ, name, want string
	}{
		{"npm scoped", manifest.TypeNpm, "@bitwarden/cli", "npm/@bitwarden--cli/@bitwarden--cli-2026.3.0.tgz"},
		{"gomod keeps its slashes", manifest.TypeGomod, "github.com/aws/aws-sdk-go", "gomod/github.com/aws/aws-sdk-go/@v/v1.2.3.zip"},
	}
	for _, c := range cases {
		got := s3Path(store, c.typ, c.name, "")
		if got != c.want {
			t.Errorf("%s:\n  got:  %s\n  want: %s", c.label, got, c.want)
		}
	}
	// git is already safe-encoded; just assert the result doesn't leak a raw '/'.
	gitPath := s3Path(store, manifest.TypeGit, "netbox-community/netbox", "")
	if strings.Contains(gitPath, "netbox-community/netbox") {
		t.Errorf("git path leaked the canonical slash form: %s", gitPath)
	}
}

// Guards that s3Path picks the VersionEntry matching the tree node's
// Version field rather than always the first one.
func TestS3PathUsesSelectedVersion(t *testing.T) {
	store := manifest.NewLocalStore(t.TempDir())
	ctx := t.Context()
	_ = store.AddVersion(ctx, manifest.TypeNpm, "pkg", manifest.VersionEntry{Version: "1.0.0"})
	_ = store.AddVersion(ctx, manifest.TypeNpm, "pkg", manifest.VersionEntry{Version: "2.0.0"})

	if got := s3Path(store, manifest.TypeNpm, "pkg", "2.0.0"); !strings.Contains(got, "2.0.0") || strings.Contains(got, "1.0.0") {
		t.Errorf("want path for 2.0.0, got %q", got)
	}
	if got := s3Path(store, manifest.TypeNpm, "pkg", "1.0.0"); !strings.Contains(got, "1.0.0") || strings.Contains(got, "2.0.0") {
		t.Errorf("want path for 1.0.0, got %q", got)
	}
	// Empty version falls back to Versions[0].
	first := s3Path(store, manifest.TypeNpm, "pkg", "")
	if !strings.Contains(first, "1.0.0") {
		t.Errorf("empty version should fall back to first entry, got %q", first)
	}
}

func TestWrapJSONLines(t *testing.T) {
	raw := `{
  "name": "pkg",
  "description": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bbbbbbbbbbbbbbbbbbbbbbbbbbbbb ccccccccc"
}`
	out := wrapJSONLines(raw, 60)
	for _, line := range strings.Split(out, "\n") {
		if len(line) > 62 { // 60 + a small fudge for the indent
			t.Errorf("line not wrapped (len=%d): %q", len(line), line)
		}
	}
	// Short lines pass through unchanged.
	if !strings.Contains(out, `"name": "pkg"`) {
		t.Errorf("short line mangled:\n%s", out)
	}
}

// --- stripAnsi ---

func TestStripAnsi(t *testing.T) {
	input := "\x1b[32mhello\x1b[0m world"
	got := stripAnsi(input)
	want := "hello world"
	if got != want {
		t.Errorf("stripAnsi(%q) = %q, want %q", input, got, want)
	}
}

// --- logPaneModel ---

func TestLogPaneAppendLog(t *testing.T) {
	lp := newLogPane()
	initialLines := len(lp.outputLines)

	lp.appendLog("line one")
	lp.appendLog("line two\nline three")

	want := initialLines + 3
	if len(lp.outputLines) != want {
		t.Errorf("outputLines len = %d, want %d", len(lp.outputLines), want)
	}
}

func TestLogPaneSetSize(t *testing.T) {
	lp := newLogPane()
	lp.SetSize(120, 20)

	if lp.width != 120 {
		t.Errorf("width = %d, want 120", lp.width)
	}
	if lp.height != 20 {
		t.Errorf("height = %d, want 20", lp.height)
	}
	if lp.viewport.Width != 120 {
		t.Errorf("viewport.Width = %d, want 120", lp.viewport.Width)
	}
	if lp.viewport.Height != 20 {
		t.Errorf("viewport.Height = %d, want 20", lp.viewport.Height)
	}
}

func TestLogPaneFocusBlur(t *testing.T) {
	lp := newLogPane()
	if lp.focused {
		t.Error("expected unfocused on creation")
	}
	lp.Focus()
	if !lp.focused {
		t.Error("expected focused after Focus()")
	}
	lp.Blur()
	if lp.focused {
		t.Error("expected unfocused after Blur()")
	}
}

func TestLogPaneView(t *testing.T) {
	lp := newLogPane()
	lp.SetSize(80, 10)
	lp.appendLog("hello world")
	v := lp.View()
	if v == "" {
		t.Error("log pane View() returned empty string")
	}
}

// --- BuildStage enum ---

func TestBuildStageValues(t *testing.T) {
	// Ensure the iota order is stable — callers depend on specific values.
	if StageFetch != 0 {
		t.Errorf("StageFetch = %d, want 0", StageFetch)
	}
	if StageBuild != 1 {
		t.Errorf("StageBuild = %d, want 1", StageBuild)
	}
	if StagePackage != 2 {
		t.Errorf("StagePackage = %d, want 2", StagePackage)
	}
	if StageDeploy != 3 {
		t.Errorf("StageDeploy = %d, want 3", StageDeploy)
	}
	if StageAll != 4 {
		t.Errorf("StageAll = %d, want 4", StageAll)
	}
}

// --- popupBuildMenu ---

func TestBuildMenuDismissOnEsc(t *testing.T) {
	p := popupModel{
		kind:           popupBuildMenu,
		buildEntryType: "apt",
		buildEntryName: "pkg-a",
	}
	if !p.Active() {
		t.Fatal("popup should be active")
	}
	dismissed := p.HandleBuildMenuKey("esc")
	if !dismissed {
		t.Error("HandleBuildMenuKey(esc) should return dismissed=true")
	}
	if p.Active() {
		t.Error("popup should be inactive after esc")
	}
}

func TestBuildMenuSelectStage(t *testing.T) {
	cases := []struct {
		key   string
		stage BuildStage
	}{
		{"f", StageFetch},
		{"F", StageFetch},
		{"b", StageBuild},
		{"B", StageBuild},
		{"p", StagePackage},
		{"P", StagePackage},
		{"d", StageDeploy},
		{"D", StageDeploy},
		{"a", StageAll},
		{"A", StageAll},
	}

	for _, tc := range cases {
		var gotStage BuildStage = -1
		p := popupModel{
			kind:           popupBuildMenu,
			buildEntryType: "git",
			buildEntryName: "repo-x",
			onBuildSelect: func(s BuildStage, force bool) tea.Cmd {
				gotStage = s
				return nil
			},
		}
		dismissed := p.HandleBuildMenuKey(tc.key)
		if !dismissed {
			t.Errorf("key %q: expected dismissed=true", tc.key)
		}
		if gotStage != tc.stage {
			t.Errorf("key %q: gotStage=%d, want %d", tc.key, gotStage, tc.stage)
		}
	}
}

// --- popupForm ---

func TestFormPopupTabNavigation(t *testing.T) {
	p := popupModel{
		kind:       popupForm,
		formTitle:  "Test Form",
		formFields: []formField{{Label: "A"}, {Label: "B"}, {Label: "C"}},
		formCursor: 0,
	}

	p.HandleFormKey("tab")
	if p.formCursor != 1 {
		t.Errorf("after tab: cursor = %d, want 1", p.formCursor)
	}

	p.HandleFormKey("tab")
	if p.formCursor != 2 {
		t.Errorf("after second tab: cursor = %d, want 2", p.formCursor)
	}

	// Wraps around.
	p.HandleFormKey("tab")
	if p.formCursor != 0 {
		t.Errorf("after wrap-around tab: cursor = %d, want 0", p.formCursor)
	}

	// Reverse with shift+tab.
	p.HandleFormKey("shift+tab")
	if p.formCursor != 2 {
		t.Errorf("after shift+tab: cursor = %d, want 2", p.formCursor)
	}
}

func TestFormPopupRuneInput(t *testing.T) {
	p := popupModel{
		kind:       popupForm,
		formFields: []formField{{Label: "Name", Value: ""}},
		formCursor: 0,
	}

	p.HandleFormRune('h')
	p.HandleFormRune('i')

	if p.formFields[0].Value != "hi" {
		t.Errorf("field value = %q, want %q", p.formFields[0].Value, "hi")
	}
}

func TestFormPopupBackspace(t *testing.T) {
	p := popupModel{
		kind:       popupForm,
		formFields: []formField{{Label: "Name", Value: "hello", cursor: 5}},
		formCursor: 0,
	}
	p.HandleFormKey("backspace")
	if p.formFields[0].Value != "hell" {
		t.Errorf("after backspace: value = %q, want %q", p.formFields[0].Value, "hell")
	}
}

func TestFormPopupSaveAndDismiss(t *testing.T) {
	saved := false
	p := popupModel{
		kind:       popupForm,
		formFields: []formField{{Label: "Name", Value: "test"}},
		onFormSave: func(fields []formField) { saved = true },
	}
	dismissed := p.HandleFormKey("enter")
	if !dismissed {
		t.Error("enter should dismiss the form")
	}
	if !saved {
		t.Error("onFormSave was not called on enter")
	}
	if p.Active() {
		t.Error("popup should be inactive after save")
	}
}

func TestFormPopupEscCancels(t *testing.T) {
	called := false
	p := popupModel{
		kind:       popupForm,
		formFields: []formField{{Label: "Name", Value: "test"}},
		onFormSave: func(fields []formField) { called = true },
	}
	dismissed := p.HandleFormKey("esc")
	if !dismissed {
		t.Error("esc should dismiss the form")
	}
	if called {
		t.Error("onFormSave should not be called on esc")
	}
}

// --- executor helpers ---

func TestIsValidTypeExecutor(t *testing.T) {
	// isValidType is now in executor.go; verify it is accessible and correct.
	for _, valid := range []string{"apt", "git", "pypi", "binary"} {
		if !isValidType(valid) {
			t.Errorf("isValidType(%q) = false, want true", valid)
		}
	}
}

func TestResolveTypesExecutor(t *testing.T) {
	types, err := resolveTypes(nil)
	if err != nil {
		t.Fatalf("resolveTypes(nil) error: %v", err)
	}
	if len(types) != len(manifest.AllTypes) {
		t.Errorf("len = %d, want %d", len(types), len(manifest.AllTypes))
	}
}

func TestLastURLSegment(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"https://example.com/foo/bar.tar.gz", "bar.tar.gz"},
		{"nopath", "nopath"},
		{"trailing/", ""},
	}
	for _, tc := range cases {
		got := lastURLSegment(tc.input)
		if got != tc.want {
			t.Errorf("lastURLSegment(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// --- detectChecksumAlgorithm ---

func TestDetectChecksumAlgorithm(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		// Empty — no algorithm.
		{"", ""},
		// MD5 (32 hex chars).
		{"d41d8cd98f00b204e9800998ecf8427e", "md5"},
		// SHA1 (40 hex chars).
		{"da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1"},
		// SHA256 (64 hex chars).
		{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256"},
		// SHA512 (128 hex chars).
		{"cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e" +
			"00000000000000000000000000000000", ""},
		// Non-hex characters.
		{"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", ""},
		// Wrong length.
		{"abc123", ""},
		// Uppercase hex.
		{"D41D8CD98F00B204E9800998ECF8427E", "md5"},
	}
	for _, tc := range cases {
		got := detectChecksumAlgorithm(tc.input)
		if got != tc.want {
			t.Errorf("detectChecksumAlgorithm(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// --- checksumHint ---

func TestChecksumHint(t *testing.T) {
	cases := []struct {
		input    string
		contains string
	}{
		{"", "(optional"},
		{"d41d8cd98f00b204e9800998ecf8427e", "md5"},
		{"da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1"},
		{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256"},
		{"notvalidhex!!!", "invalid"},
	}
	for _, tc := range cases {
		got := checksumHint(tc.input)
		if !strings.Contains(got, tc.contains) {
			t.Errorf("checksumHint(%q) = %q, want to contain %q", tc.input, got, tc.contains)
		}
	}
}

// --- extractNameFromURL ---

func TestExtractNameFromURL(t *testing.T) {
	cases := []struct {
		url       string
		entryType string
		want      string
	}{
		{"https://github.com/org/netbox.git", manifest.TypeGit, "org/netbox"},
		{"https://github.com/org/repo", manifest.TypeGit, "org/repo"},
		{"https://example.com/downloads/awscli-2.0.tar.gz", manifest.TypeBinary, "awscli-2.0"},
		{"https://example.com/pkg.deb", manifest.TypeApt, "pkg"},
		{"https://example.com/tool.zip", manifest.TypeBinary, "tool"},
		{"https://example.com/", manifest.TypeBinary, ""},
	}
	for _, tc := range cases {
		got := extractNameFromURL(tc.url, tc.entryType)
		if got != tc.want {
			t.Errorf("extractNameFromURL(%q, %q) = %q, want %q", tc.url, tc.entryType, got, tc.want)
		}
	}
}

// --- rebuildCreateFields ---

func TestRebuildCreateFieldsPreservesValues(t *testing.T) {
	// Start with default apt fields and populate some values.
	fields := rebuildCreateFields(manifest.TypeApt, nil)
	setFieldValue(fields, "Name", "mypkg")
	setFieldValue(fields, "Version", "1.2.3")

	// Switch to binary — common fields (Name) should be preserved.
	fields = rebuildCreateFields(manifest.TypeBinary, fields)
	if got := fieldValueFromSlice(fields, "Name"); got != "mypkg" {
		t.Errorf("Name after type switch = %q, want %q", got, "mypkg")
	}
}

func TestRebuildCreateFieldsGit(t *testing.T) {
	fields := rebuildCreateFields(manifest.TypeGit, nil)
	labels := make([]string, len(fields))
	for i, f := range fields {
		labels[i] = f.Label
	}
	for _, required := range []string{"Type", "Name", "Source URL", "Ref"} {
		found := false
		for _, l := range labels {
			if l == required {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("git fields missing %q; got %v", required, labels)
		}
	}
}

func TestRebuildCreateFieldsBinary(t *testing.T) {
	fields := rebuildCreateFields(manifest.TypeBinary, nil)
	labels := make([]string, len(fields))
	for i, f := range fields {
		labels[i] = f.Label
	}
	for _, required := range []string{"Type", "Name", "Version", "Source URL", "Checksum", "Latest"} {
		found := false
		for _, l := range labels {
			if l == required {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("binary fields missing %q; got %v", required, labels)
		}
	}
}

// --- validateCreateFields ---

func TestValidateCreateFields(t *testing.T) {
	cases := []struct {
		name    string
		fields  []formField
		wantErr bool
	}{
		{
			name: "valid apt",
			fields: []formField{
				{Label: "Type", Value: "apt"},
				{Label: "Name", Value: "mypkg"},
			},
			wantErr: false,
		},
		{
			name: "missing name",
			fields: []formField{
				{Label: "Type", Value: "apt"},
				{Label: "Name", Value: ""},
			},
			wantErr: true,
		},
		{
			name: "git missing URL",
			fields: []formField{
				{Label: "Type", Value: "git"},
				{Label: "Name", Value: "repo"},
				{Label: "Source URL", Value: ""},
				{Label: "Ref", Value: "main"},
			},
			wantErr: true,
		},
		{
			name: "git missing Ref",
			fields: []formField{
				{Label: "Type", Value: "git"},
				{Label: "Name", Value: "repo"},
				{Label: "Source URL", Value: "https://example.com/repo.git"},
				{Label: "Ref", Value: ""},
			},
			wantErr: true,
		},
		{
			name: "invalid checksum",
			fields: []formField{
				{Label: "Type", Value: "binary"},
				{Label: "Name", Value: "tool"},
				{Label: "Source URL", Value: "https://example.com/tool"},
				{Label: "Checksum", Value: "notahex!!!"},
			},
			wantErr: true,
		},
		{
			name: "valid binary with checksum",
			fields: []formField{
				{Label: "Type", Value: "binary"},
				{Label: "Name", Value: "tool"},
				{Label: "Source URL", Value: "https://example.com/tool"},
				{Label: "Checksum", Value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
				{Label: "Skip validation", Value: "yes", Checkbox: true},
			},
			wantErr: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := validateCreateFields(tc.fields)
			if (got != "") != tc.wantErr {
				t.Errorf("validateCreateFields() = %q, wantErr=%v", got, tc.wantErr)
			}
		})
	}
}

// --- Select field behavior ---

func TestSelectFieldOpenClose(t *testing.T) {
	p := popupModel{
		kind: popupForm,
		formFields: []formField{
			{
				Label:   "Type",
				Value:   "apt",
				Select:  true,
				Options: []string{"apt", "git", "pypi", "binary"},
			},
		},
		formCursor: 0,
	}

	// Space should open the submenu.
	p.HandleFormKey(" ")
	if !p.selectOpen {
		t.Error("Space on Select field should open submenu")
	}

	// Down navigates the submenu.
	p.HandleFormKey("down")
	if p.selectCursor != 1 {
		t.Errorf("after down: selectCursor = %d, want 1", p.selectCursor)
	}

	// Enter selects and closes.
	p.HandleFormKey("enter")
	if p.selectOpen {
		t.Error("enter should close submenu")
	}
	if p.formFields[0].Value != "git" {
		t.Errorf("after select: Value = %q, want %q", p.formFields[0].Value, "git")
	}
}

func TestSelectFieldEscDiscards(t *testing.T) {
	p := popupModel{
		kind: popupForm,
		formFields: []formField{
			{
				Label:   "Type",
				Value:   "apt",
				Select:  true,
				Options: []string{"apt", "git", "pypi", "binary"},
			},
		},
		formCursor: 0,
	}

	p.HandleFormKey(" ")
	p.HandleFormKey("down") // move to "git"
	p.HandleFormKey("esc")  // discard

	if p.selectOpen {
		t.Error("esc should close submenu")
	}
	if p.formFields[0].Value != "apt" {
		t.Errorf("after esc: Value = %q, want %q (no change)", p.formFields[0].Value, "apt")
	}
	// The popup itself should still be active.
	if !p.Active() {
		t.Error("popup should still be active after submenu esc")
	}
}

// --- Disabled field skipping ---

func TestDisabledFieldsSkippedByTab(t *testing.T) {
	p := popupModel{
		kind: popupForm,
		formFields: []formField{
			{Label: "A", Value: "first"},
			{Label: "B", Value: "disabled", Disabled: true},
			{Label: "C", Value: "third"},
		},
		formCursor: 0,
	}

	// Tab from A should skip B (disabled) and land on C.
	p.HandleFormKey("tab")
	if p.formCursor != 2 {
		t.Errorf("tab skipping disabled: cursor = %d, want 2", p.formCursor)
	}
}

func TestDisabledFieldIgnoresRune(t *testing.T) {
	p := popupModel{
		kind: popupForm,
		formFields: []formField{
			{Label: "V", Value: "original", Disabled: true},
		},
		formCursor: 0,
	}

	p.HandleFormRune('x')
	if p.formFields[0].Value != "original" {
		t.Errorf("disabled field value changed to %q", p.formFields[0].Value)
	}
}

// --- updateChecksumHint (Latest ↔ Version coupling) ---

func TestUpdateChecksumHintLatestCoupling(t *testing.T) {
	fields := rebuildCreateFields(manifest.TypeBinary, nil)
	setFieldValue(fields, "Latest", "yes")
	updateChecksumHint(fields)

	// Version text (NoLabel field) should be forced to "latest" and disabled.
	for _, f := range fields {
		if f.Label == "Version" && f.LabelSelect {
			if !f.Disabled {
				t.Error("Version text should be disabled when Latest=yes")
			}
			if f.Value != "latest" {
				t.Errorf("Version text value = %q, want latest", f.Value)
			}
		}
	}
}

func TestUpdateChecksumHintLatestOff(t *testing.T) {
	fields := rebuildCreateFields(manifest.TypeBinary, nil)
	setFieldValue(fields, "Latest", "yes")
	updateChecksumHint(fields)
	setFieldValue(fields, "Latest", "no")
	updateChecksumHint(fields)

	for _, f := range fields {
		if f.Label == "Version" && f.LabelSelect {
			if f.Disabled {
				t.Error("Version text should be enabled when Latest=no")
			}
			if f.Value == "latest" {
				t.Error("Version text should be cleared when Latest toggled off")
			}
		}
	}
}

// --- JSON overlay ---

func TestJSONOverlayOpenClose(t *testing.T) {
	p := popupModel{kind: popupForm, formFields: []formField{{Label: "Type", Value: "apt"}}}

	if p.jsonInput {
		t.Fatal("jsonInput should be false initially")
	}

	p.OpenJSONOverlay(120, 40, "", "")

	if !p.jsonInput {
		t.Error("jsonInput should be true after OpenJSONOverlay")
	}

	// Esc closes without applying.
	escMsg := tea.KeyMsg{Type: tea.KeyEscape}
	dismissed, _ := p.HandleJSONOverlayKey(escMsg, func(string) string { return "" })
	if !dismissed {
		t.Error("esc should close the overlay")
	}
	if p.jsonInput {
		t.Error("jsonInput should be false after esc")
	}
}

func TestJSONOverlayApplyError(t *testing.T) {
	p := popupModel{kind: popupForm, jsonInput: true}
	p.OpenJSONOverlay(120, 40, "", "")

	applyFn := func(string) string { return "bad json" }
	ctrlS := tea.KeyMsg{Type: tea.KeyCtrlS}
	dismissed, _ := p.HandleJSONOverlayKey(ctrlS, applyFn)
	if dismissed {
		t.Error("ctrl+s should keep overlay open on error")
	}
	if p.jsonError != "bad json" {
		t.Errorf("jsonError = %q, want %q", p.jsonError, "bad json")
	}
}

// --- setFieldValue / fieldValueFromSlice ---

func TestSetFieldValue(t *testing.T) {
	fields := []formField{{Label: "X", Value: "old"}}
	setFieldValue(fields, "X", "new")
	if fields[0].Value != "new" {
		t.Errorf("Value = %q, want new", fields[0].Value)
	}
	if fields[0].cursor != 3 {
		t.Errorf("cursor = %d, want 3", fields[0].cursor)
	}
}

func TestFieldValueFromSlice(t *testing.T) {
	fields := []formField{{Label: "A", Value: "alpha"}, {Label: "B", Value: "beta"}}
	if got := fieldValueFromSlice(fields, "B"); got != "beta" {
		t.Errorf("got %q, want beta", got)
	}
	if got := fieldValueFromSlice(fields, "Z"); got != "" {
		t.Errorf("absent key: got %q, want empty", got)
	}
}

// Guards that the client snippets the details pane emits follow the scheme the
// server is configured to answer on. An http:// snippet for a TLS server is
// unauthenticated delivery to a root-privileged installer, since apt needs
// [trusted=yes] against an unsigned repository.
func TestClientURLSchemeFollowsTLSConfig(t *testing.T) {
	store := manifest.NewLocalStore(t.TempDir())
	ctx := t.Context()
	_ = store.AddVersion(ctx, manifest.TypeApt, "pkg-a", manifest.VersionEntry{Version: "1.0"})
	_ = store.AddVersion(ctx, manifest.TypePypi, "pkg-b", manifest.VersionEntry{Version: "1.0"})
	_ = store.AddVersion(ctx, manifest.TypeGomod, "example.com/m", manifest.VersionEntry{Version: "v1.0.0"})
	_ = store.AddVersion(ctx, manifest.TypeNpm, "pkg-c", manifest.VersionEntry{Version: "1.0.0"})
	_ = store.AddVersion(ctx, manifest.TypeHelm, "chart", manifest.VersionEntry{Version: "1.0.0"})
	_ = store.AddVersion(ctx, manifest.TypeGit, "org/repo", manifest.VersionEntry{Ref: "v1.0.0"})
	_ = store.AddVersion(ctx, manifest.TypeBinary, "tool", manifest.VersionEntry{Version: "1.0.0", Filename: "tool"})

	// apt is absent on purpose: a sources line is not a URL, and it needs the
	// served suites and the signing state as well as the base. See
	// TestAptSourcesFollowsServerState.
	entries := []struct{ typ, name string }{
		{manifest.TypePypi, "pkg-b"},
		{manifest.TypeGomod, "example.com/m"},
		{manifest.TypeNpm, "pkg-c"},
		{manifest.TypeHelm, "chart"},
		{manifest.TypeGit, "org/repo"},
		{manifest.TypeBinary, "tool"},
	}

	tlsCfg := &config.Config{TLSCert: "/etc/bodega/cert.pem", TLSKey: "/etc/bodega/key.pem"}
	for _, e := range entries {
		got := clientURL(tlsCfg, store, e.typ, e.name)
		if got == "" {
			t.Fatalf("%s: empty client URL", e.typ)
		}
		if !strings.Contains(got, "https://") {
			t.Errorf("%s with TLS configured: want https://, got %q", e.typ, got)
		}
		if strings.Contains(got, "http://") {
			t.Errorf("%s with TLS configured: leaked http://, got %q", e.typ, got)
		}
	}

	plainCfg := &config.Config{}
	for _, e := range entries {
		got := clientURL(plainCfg, store, e.typ, e.name)
		if !strings.Contains(got, "http://") {
			t.Errorf("%s without TLS: want http://, got %q", e.typ, got)
		}
	}

	// A cert with no key does not start a TLS listener, so it must not
	// advertise one.
	halfCfg := &config.Config{TLSCert: "/etc/bodega/cert.pem"}
	if got := clientURL(halfCfg, store, manifest.TypePypi, "pkg-b"); !strings.Contains(got, "http://") {
		t.Errorf("cert without key: want http://, got %q", got)
	}

	// public_url outranks the TLS pair everywhere, not only on the apt line.
	// The pair describes this host's listener; behind a proxy both keys are
	// empty here and every client still speaks https.
	proxiedCfg := &config.Config{PublicURL: "https://bodega.example.com"}
	for _, e := range entries {
		got := clientURL(proxiedCfg, store, e.typ, e.name)
		if !strings.Contains(got, "https://bodega.example.com/") {
			t.Errorf("%s behind a proxy: want the public URL, got %q", e.typ, got)
		}
	}
}

// The apt pane emits what the server serves: the package's own suite, the
// public URL in force, and the form the signing state calls for. Each of the
// three was guessed at once, and each guess shipped as a caveat.
func TestAptSourcesFollowsServerState(t *testing.T) {
	pm := &manifest.PackageManifest{
		Name: "pkg-a",
		Versions: []manifest.VersionEntry{
			{Version: "1.0", Suites: []string{"jammy"}},
		},
	}
	cfg := &config.Config{
		AptCodename: "noble",
		AptSuites:   []string{"noble", "jammy"},
		PublicURL:   "https://bodega.example.com",
	}

	signed := aptSources(cfg, pm, true)
	if !strings.Contains(signed.OneLine, " jammy main") {
		t.Errorf("suite comes from the package, not the default: %q", signed.OneLine)
	}
	if !strings.Contains(signed.OneLine, "https://bodega.example.com/apt/") {
		t.Errorf("URL comes from public_url: %q", signed.OneLine)
	}
	if strings.Contains(signed.OneLine, "trusted=yes") {
		t.Errorf("signed instance told the operator to turn verification off: %q", signed.OneLine)
	}
	if !strings.Contains(signed.Deb822, "Signed-By: ") {
		t.Errorf("signed instance emits no Signed-By:\n%s", signed.Deb822)
	}

	unsigned := aptSources(cfg, pm, false)
	if !strings.Contains(unsigned.OneLine, "[trusted=yes]") {
		t.Errorf("unsigned instance emits no fallback: %q", unsigned.OneLine)
	}
	if unsigned.Note() == "" {
		t.Error("unsigned instance emits [trusted=yes] with no consequence beside it")
	}

	// No public_url and no local TLS: the host is a placeholder, and the pane
	// has to say so rather than let it read as an address.
	bare := aptSources(&config.Config{AptCodename: "noble"}, nil, false)
	if !strings.Contains(bare.OneLine, aptsources.PlaceholderHost) {
		t.Errorf("no public_url: want a placeholder host, got %q", bare.OneLine)
	}
	if !strings.Contains(bare.Note(), "public_url") {
		t.Errorf("placeholder host with no note: %q", bare.Note())
	}
	if !strings.Contains(bare.OneLine, " noble main") {
		t.Errorf("no package in hand: want the server default suite, got %q", bare.OneLine)
	}
}

// --- audit results table ---

// auditTestEvents mirror the rows that broke the old fixed-width format string:
// serve_fetch overruns %-8s and the InRelease paths overrun %-30s.
func auditTestEvents() []audit.StoredEvent {
	ts := time.Date(2026, 9, 6, 10, 43, 27, 0, time.UTC)
	names := []string{
		"dists/jammy-auth-51/InRelease",
		"dists/jammy-backports/InRelease",
		"dists/jammy-security/InRelease",
		"nginx",
	}
	events := make([]audit.StoredEvent, 0, len(names))
	for _, n := range names {
		events = append(events, audit.StoredEvent{
			Timestamp: ts,
			Event: audit.Event{
				EventType: "serve_fetch",
				PkgType:   "apt",
				PkgName:   n,
				Status:    "success",
				ClientIP:  "172.233.223.16",
			},
		})
	}
	return events
}

func TestAuditTableColumnsAlign(t *testing.T) {
	tbl := newAuditTable(auditTestEvents(), 200, 40)
	lines := strings.Split(ansi.Strip(tbl.View()), "\n")
	if len(lines) < 5 {
		t.Fatalf("table rendered %d lines, want header plus 4 rows", len(lines))
	}

	header := lines[0]
	statusCol := strings.Index(header, "STATUS")
	if statusCol < 0 {
		t.Fatalf("no STATUS column in header %q", header)
	}
	for i, line := range lines[1:] {
		if got := strings.Index(line, "success"); got != statusCol {
			t.Errorf("row %d: STATUS at column %d, want %d\nheader: %q\nrow:    %q",
				i, got, statusCol, header, line)
		}
		if lipgloss.Width(line) != lipgloss.Width(header) {
			t.Errorf("row %d width %d, header width %d", i, lipgloss.Width(line), lipgloss.Width(header))
		}
	}
}

func TestAuditTableNameTruncatesWithinBudget(t *testing.T) {
	// A narrow screen has to come out of NAME, not out of the columns to its
	// right: every row still ends at the same column.
	tbl := newAuditTable(auditTestEvents(), 90, 40)
	lines := strings.Split(ansi.Strip(tbl.View()), "\n")
	header := lines[0]
	for i, line := range lines[1:] {
		if lipgloss.Width(line) != lipgloss.Width(header) {
			t.Errorf("row %d width %d, header width %d", i, lipgloss.Width(line), lipgloss.Width(header))
		}
	}
	if w := lipgloss.Width(header); w > 90 {
		t.Errorf("table width %d exceeds the 90-column screen", w)
	}
}

// --- log pane search ---

func newTestLogPane(lines ...string) logPaneModel {
	m := newLogPane()
	m.outputLines = nil
	m.SetSize(80, 3)
	for _, l := range lines {
		m.appendLog(l)
	}
	return m
}

func TestLogSearchJumpsToFirstMatch(t *testing.T) {
	m := newTestLogPane("alpha", "beta", "gamma apt", "delta", "epsilon apt", "zeta")

	m.SetSearch("apt", false)

	if got := m.MatchCount(); got != 2 {
		t.Fatalf("MatchCount = %d, want 2", got)
	}
	if got := m.MatchLine(); got != 2 {
		t.Errorf("MatchLine = %d, want 2 (the first matching line)", got)
	}
	if got := m.viewport.YOffset; got != 2 {
		t.Errorf("viewport YOffset = %d, want 2", got)
	}

	m.NextMatch()
	if got := m.MatchLine(); got != 4 {
		t.Errorf("after NextMatch, MatchLine = %d, want 4", got)
	}
	m.NextMatch()
	if got := m.MatchLine(); got != 2 {
		t.Errorf("NextMatch should wrap to 2, got %d", got)
	}
	m.PrevMatch()
	if got := m.MatchLine(); got != 4 {
		t.Errorf("PrevMatch should wrap to 4, got %d", got)
	}
}

func TestLogSearchIsCaseInsensitive(t *testing.T) {
	m := newTestLogPane("Fetching APT index", "done")
	m.SetSearch("apt", false)
	if got := m.MatchCount(); got != 1 {
		t.Errorf("MatchCount = %d, want 1", got)
	}
}

func TestLogSearchMatchesThroughStyling(t *testing.T) {
	m := newTestLogPane(errorStyle.Render("Edit failed: bad json"), "quiet line")
	m.SetSearch("bad json", false)
	if got := m.MatchCount(); got != 1 {
		t.Errorf("MatchCount = %d, want 1 — the query must match past the ANSI styling", got)
	}
}

func TestLogFilterHidesNonMatchingLines(t *testing.T) {
	m := newTestLogPane("alpha", "beta apt", "gamma", "delta apt")

	m.SetSearch("apt", true)

	if len(m.display) != 2 {
		t.Fatalf("display holds %d lines, want 2", len(m.display))
	}
	view := ansi.Strip(m.View())
	if strings.Contains(view, "alpha") || strings.Contains(view, "gamma") {
		t.Errorf("filtered view still shows non-matching lines:\n%s", view)
	}

	m.ClearSearch()
	if len(m.display) != 4 {
		t.Errorf("after ClearSearch display holds %d lines, want all 4", len(m.display))
	}
	if m.Searching() {
		t.Error("Searching() should be false after ClearSearch")
	}
}

func TestLogSearchKeysDriveThePane(t *testing.T) {
	m := newAppModel(&config.Config{}, nil, nil, nil, nil)
	m.width, m.height = 120, 40
	m.focus = focusLog
	m.log.outputLines = nil
	for _, l := range []string{"alpha", "beta apt", "gamma"} {
		m.log.appendLog(l)
	}

	next, _ := m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("/")})
	am := next.(appModel)
	if !am.logSearchMode {
		t.Fatal("/ should open the log query")
	}
	for _, r := range "apt" {
		next, _ = am.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		am = next.(appModel)
	}
	if got := am.log.MatchCount(); got != 1 {
		t.Errorf("MatchCount = %d, want 1", got)
	}
	if !strings.Contains(ansi.Strip(am.logSearchIndicator()), "/apt (1/1)") {
		t.Errorf("title indicator = %q", ansi.Strip(am.logSearchIndicator()))
	}

	next, _ = am.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	am = next.(appModel)
	if am.logSearchMode {
		t.Error("enter should leave the query committed, not still editing")
	}
	if !am.log.Searching() {
		t.Error("enter should keep the query active")
	}

	// Esc in the focused pane clears the query before it changes focus.
	next, _ = am.handleKey(tea.KeyMsg{Type: tea.KeyEscape})
	am = next.(appModel)
	if am.log.Searching() {
		t.Error("esc should clear the query")
	}
	if am.focus != focusLog {
		t.Error("the first esc should keep focus on the log pane")
	}
}

func TestAuditTableDropsEmptyColumns(t *testing.T) {
	header := strings.Split(ansi.Strip(newAuditTable(auditTestEvents(), 200, 40).View()), "\n")[0]
	if strings.Contains(header, "DURATION") {
		t.Errorf("no event carried a duration, so DURATION should be dropped: %q", header)
	}

	withDur := auditTestEvents()
	withDur[0].DurationMs = 12
	header = strings.Split(ansi.Strip(newAuditTable(withDur, 200, 40).View()), "\n")[0]
	if !strings.Contains(header, "DURATION") {
		t.Errorf("DURATION should be kept once an event carries one: %q", header)
	}
}

func TestElideHead(t *testing.T) {
	tests := []struct {
		in   string
		w    int
		want string
	}{
		{"dists/jammy-updates/InRelease", 15, "…ates/InRelease"},
		{"nginx", 15, "nginx"},
		{"nginx", 5, "nginx"},
		{"nginx", 1, "nginx"},
	}
	for _, tc := range tests {
		if got := elideHead(tc.in, tc.w); got != tc.want {
			t.Errorf("elideHead(%q, %d) = %q, want %q", tc.in, tc.w, got, tc.want)
		}
	}
}
