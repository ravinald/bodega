package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/scaleapi/bodega/internal/config"
	"github.com/scaleapi/bodega/internal/manifest"
	"github.com/scaleapi/bodega/internal/s3"
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

	statuses := []s3.EntryStatus{
		{Type: manifest.TypeApt, Name: "pkg-a@1.0", InS3: true},
		{Type: manifest.TypeGit, Name: "repo-b@main", InS3: false},
		{Type: manifest.TypePypi, Name: "wheels", InS3: true},
		{Type: manifest.TypeBinary, Name: "tool-c", InS3: false},
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
	for _, required := range []string{"Type", "Name", "URL", "Ref"} {
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
	for _, required := range []string{"Type", "Name", "Version", "URL", "Checksum", "Latest"} {
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
				{Label: "URL", Value: ""},
				{Label: "Ref", Value: "main"},
			},
			wantErr: true,
		},
		{
			name: "git missing Ref",
			fields: []formField{
				{Label: "Type", Value: "git"},
				{Label: "Name", Value: "repo"},
				{Label: "URL", Value: "https://example.com/repo.git"},
				{Label: "Ref", Value: ""},
			},
			wantErr: true,
		},
		{
			name: "invalid checksum",
			fields: []formField{
				{Label: "Type", Value: "binary"},
				{Label: "Name", Value: "tool"},
				{Label: "URL", Value: "https://example.com/tool"},
				{Label: "Checksum", Value: "notahex!!!"},
			},
			wantErr: true,
		},
		{
			name: "valid binary with checksum",
			fields: []formField{
				{Label: "Type", Value: "binary"},
				{Label: "Name", Value: "tool"},
				{Label: "URL", Value: "https://example.com/tool"},
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
