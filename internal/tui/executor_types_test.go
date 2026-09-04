package tui

import (
	"bytes"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/ravinald/bodega/internal/builder"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
)

// stageRunners are the per-type switches the TUI dispatches through. Four of
// the eight types fell off every one of them and the miss was silent: the
// switch matched nothing, the function returned nil, and executeStage set
// refresh=true on a run that had done nothing.
var stageRunners = map[string]func(buf *bytes.Buffer, bc *builder.Config, store *manifest.Store, typ string) error{
	// runFetch builds its own builder.Config, so it takes the roots through a
	// config.Config. An empty one resolves every per-type root to the working
	// directory, which is how this test first wrote a pypi artifact into the
	// package source tree.
	"fetch": func(buf *bytes.Buffer, bc *builder.Config, store *manifest.Store, typ string) error {
		return runFetch(buf, &config.Config{BuildRoot: bc.BuildRoot, ManifestDir: bc.ManifestDir}, store, []string{typ})
	},
	"build": func(buf *bytes.Buffer, bc *builder.Config, store *manifest.Store, typ string) error {
		return runBuildStage(buf, bc, store, typ, "")
	},
	"package": func(buf *bytes.Buffer, bc *builder.Config, store *manifest.Store, typ string) error {
		return runPackageStage(buf, bc, store, typ, "")
	},
}

// TestEveryStageAccountsForEveryType. An empty manifest is the point: with no
// entries a covered type produces a summary or a stated reason, and an
// uncovered one produces silence. That silence is what "gomod reports success
// having done nothing" looked like from the log pane.
func TestEveryStageAccountsForEveryType(t *testing.T) {
	for _, stage := range []string{"fetch", "build", "package"} {
		for _, typ := range manifest.AllTypes {
			t.Run(stage+"/"+typ, func(t *testing.T) {
				root := t.TempDir()
				store := manifest.NewLocalStore(t.TempDir())
				var buf bytes.Buffer
				bc := &builder.Config{BuildRoot: root, ManifestDir: root, Stdout: &buf}
				// A failure is fine and often right on an empty manifest —
				// PackagePypi has no wheels to index. Silence is not: it is
				// the switch having no arm, which is what let StageAll on a
				// gomod entry return nil with an empty log pane.
				_ = stageRunners[stage](&buf, bc, store, typ)
				if strings.TrimSpace(buf.String()) == "" {
					t.Errorf("%s %s produced no output at all; the switch has no arm for it", stage, typ)
				}
			})
		}
	}
}

// An entry type no arm covers is named rather than skipped. Nothing in the
// tree passes one today — resolveTypes gates on AllTypes — so this is the
// guard that keeps a ninth type from arriving as a silent success.
func TestStagesNameAnUnhandledType(t *testing.T) {
	store := manifest.NewLocalStore(t.TempDir())
	bc := &builder.Config{BuildRoot: t.TempDir(), ManifestDir: t.TempDir()}
	for name, run := range stageRunners {
		var buf bytes.Buffer
		err := run(&buf, bc, store, "quicklisp")
		if err == nil {
			t.Errorf("%s accepted an unknown type and reported success", name)
			continue
		}
		if !strings.Contains(err.Error(), "quicklisp") {
			t.Errorf("%s error does not name the type: %v", name, err)
		}
	}
}

// executeStage's own switch is the outer half of the same shape: an
// unrecognized stage must not return a nil error with an empty buffer.
func TestExecuteStageNamesAnUnhandledStage(t *testing.T) {
	store := manifest.NewLocalStore(t.TempDir())
	cfg := &config.Config{BuildRoot: t.TempDir(), ManifestDir: t.TempDir()}
	msg := executeStage(BuildStage(99), manifest.TypeGomod, "example.com/m", cfg, store, nil)()
	out, ok := msg.(cmdOutputMsg)
	if !ok {
		t.Fatalf("executeStage returned %T, want cmdOutputMsg", msg)
	}
	if out.err == nil {
		t.Fatal("an unhandled stage reported success")
	}
	if out.refresh {
		t.Error("an unhandled stage asked the tree to refresh")
	}
}

// resolveTypes is the gate every stage runs behind, so its rejection has to
// name the types that exist rather than the four it used to know.
func TestResolveTypesNamesEveryType(t *testing.T) {
	_, err := resolveTypes([]string{"quicklisp"})
	if err == nil {
		t.Fatal("resolveTypes accepted an unknown type")
	}
	for _, typ := range manifest.AllTypes {
		if !strings.Contains(err.Error(), typ) {
			t.Errorf("rejection does not offer %q: %v", typ, err)
		}
	}
}

// The config form no longer edits deny_list. E1 moved it into the audit
// database, where the config file seeds it on first start and is inert after,
// so the field accepted a value, saved it, reported success and changed
// nothing about who the server refuses.
func TestConfigFormDoesNotEditTheACL(t *testing.T) {
	m := appModel{cfg: &config.Config{ManifestDir: t.TempDir()}, store: manifest.NewLocalStore(t.TempDir())}
	m.details = newDetailsModel(m.store, m.cfg)
	next, _ := m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("C")})
	got, ok := next.(appModel)
	if !ok {
		t.Fatalf("handleKey returned %T", next)
	}
	if got.popup.kind != popupForm {
		t.Fatalf("C did not open the config form: kind = %v", got.popup.kind)
	}
	for _, f := range got.popup.formFields {
		if strings.Contains(strings.ToLower(f.Label), "deny") {
			t.Errorf("config form still carries the %q field", f.Label)
		}
	}
	if !strings.Contains(got.popup.formNote, "bodega acl deny") {
		t.Errorf("config form does not name the command that edits the deny list: %q", got.popup.formNote)
	}
	if !strings.Contains(got.popup.renderForm(), "bodega acl deny") {
		t.Error("the note is set but never rendered, so the operator cannot read it")
	}
}
