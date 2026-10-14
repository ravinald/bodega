package tui

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
)

func typeKeys(v *queueView, s string) {
	for _, r := range s {
		if r == ' ' {
			v.handleKey(tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}})
			continue
		}
		v.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
}

// The Q view resolves the row under the cursor through the same functions as
// the CLI: a dismissal takes the reason typed at the prompt, and an approval
// of known malware is refused with the check named and the row left open.
func TestQueueViewDismissesAndRefusesMalware(t *testing.T) {
	adb, err := audit.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = adb.Close() })
	t0 := time.Now().Add(-time.Minute)
	for i, f := range []audit.QueueRefusal{
		{PkgType: "npm", PkgName: "evil", PkgVersion: "1.0.0", Check: admit.QueueMalware},
		{PkgType: "npm", PkgName: "lodahs", PkgVersion: "1.0.0", Check: admit.QueueAllowList, Pattern: "lodahs"},
	} {
		if err := adb.RecordRefusal(t.Context(), f, t0.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	v := newQueueView(adb, &config.Config{})
	if len(v.rows) != 2 || v.rows[0].PkgName != "lodahs" {
		t.Fatalf("rows = %+v, want lodahs first", v.rows)
	}

	v.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'x'}})
	typeKeys(v, "typo of lodash")
	if !strings.Contains(v.render(), "Reason to dismiss: typo of lodash_") {
		t.Fatalf("prompt not shown:\n%s", v.render())
	}
	v.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	if !strings.HasPrefix(v.status, "Dismissed ") || len(v.rows) != 1 {
		t.Fatalf("after dismiss: status %q, rows %+v", v.status, v.rows)
	}

	v.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'a'}})
	typeKeys(v, "please")
	v.handleKey(tea.KeyMsg{Type: tea.KeyEnter})
	if !strings.Contains(v.status, "refused by malware") || len(v.rows) != 1 {
		t.Errorf("approving malware: status %q, rows %+v", v.status, v.rows)
	}
	if !v.handleKey(tea.KeyMsg{Type: tea.KeyEsc}) {
		t.Error("Esc did not close the view")
	}
}

// Q from the Sources pane opens the view, and Esc closes it.
func TestQKeyOpensTheQueue(t *testing.T) {
	m := newAppModel(&config.Config{}, nil, nil, nil, nil)
	next, _ := m.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'Q'}})
	am := next.(appModel)
	if am.popup.kind != popupQueue || am.popup.queue == nil {
		t.Fatalf("Q opened popup kind %d", am.popup.kind)
	}
	if !strings.Contains(am.popup.View(120, 40), "No audit database is open") {
		t.Errorf("with no audit db the view should say so:\n%s", am.popup.View(120, 40))
	}
	next, _ = am.handleKey(tea.KeyMsg{Type: tea.KeyEsc})
	if closed := next.(appModel); closed.popup.Active() {
		t.Error("Esc left the queue open")
	}
}
