package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
)

// queueView is the Q popup: the open rows of the refusal queue, with approve
// and dismiss acting on the row under the cursor. Both resolutions need a
// reason, so either key opens a one-line prompt for it rather than acting at
// once; Enter on the prompt resolves, Esc abandons it.
//
// It resolves through admit.ApproveQueued and admit.DismissQueued, the
// functions the CLI and the API call, so a row approved here is approved by
// the same rules and recorded under the same actor `bodega queue` would use.
type queueView struct {
	db  *audit.DB
	cfg *config.Config
	now func() time.Time

	rows   []audit.QueueRow
	cursor int

	// action is "approve" or "dismiss" while the reason prompt is open.
	action string
	reason string
	// status is the outcome of the last resolution or load, shown under the
	// table until the next one replaces it.
	status string
}

func newQueueView(db *audit.DB, cfg *config.Config) *queueView {
	v := &queueView{db: db, cfg: cfg, now: time.Now}
	v.reload()
	return v
}

func (v *queueView) reload() {
	if v.db == nil {
		v.status = "No audit database is open; the queue is recorded there."
		return
	}
	rows, err := v.db.ListQueue(context.Background(), audit.QueueFilter{State: audit.QueueOpen})
	if err != nil {
		v.status = "Could not read the queue: " + err.Error()
		return
	}
	v.rows = rows
	if v.cursor >= len(v.rows) {
		v.cursor = max(0, len(v.rows)-1)
	}
}

// handleKey reports whether the popup should close.
func (v *queueView) handleKey(msg tea.KeyMsg) bool {
	key := msg.String()
	if v.action != "" {
		switch {
		case key == "esc":
			v.action, v.reason = "", ""
		case key == "enter":
			v.resolve()
		case key == "backspace":
			if r := []rune(v.reason); len(r) > 0 {
				v.reason = string(r[:len(r)-1])
			}
		case msg.Type == tea.KeyRunes:
			v.reason += string(msg.Runes)
		case msg.Type == tea.KeySpace:
			v.reason += " "
		}
		return false
	}
	switch key {
	case "esc", "q":
		return true
	case "up", "k":
		if v.cursor > 0 {
			v.cursor--
		}
	case "down", "j":
		if v.cursor < len(v.rows)-1 {
			v.cursor++
		}
	case "a":
		if len(v.rows) > 0 {
			v.action, v.reason, v.status = "approve", "", ""
		}
	case "x":
		if len(v.rows) > 0 {
			v.action, v.reason, v.status = "dismiss", "", ""
		}
	case "r":
		v.status = ""
		v.reload()
	}
	return false
}

func (v *queueView) resolve() {
	row := v.rows[v.cursor]
	ctx := context.Background()
	actor := audit.CurrentActor()
	if v.action == "approve" {
		res, err := admit.ApproveQueued(ctx, v.db, v.cfg, row.ID, actor, admit.QueueApproval{Reason: v.reason}, v.now())
		if err != nil {
			v.status = "Not approved: " + err.Error()
		} else {
			v.status = fmt.Sprintf("Approved %d: %s.", row.ID, res.Row.Resolution)
			if res.Override != nil && res.Override.Status == audit.OverrideStatusPending {
				v.status += fmt.Sprintf(" It applies once another identity runs: bodega override approve %s", res.Override.ID)
			}
			if res.Warning != "" {
				v.status += " Warning: " + res.Warning
			}
		}
	} else {
		if _, err := admit.DismissQueued(ctx, v.db, row.ID, actor, v.reason, v.now()); err != nil {
			v.status = "Not dismissed: " + err.Error()
		} else {
			v.status = fmt.Sprintf("Dismissed %d.", row.ID)
		}
	}
	v.action, v.reason = "", ""
	v.reload()
}

func (v *queueView) render() string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "Refusal queue: %d open\n", len(v.rows))
	sb.WriteString(strings.Repeat("─", 78) + "\n\n")
	if len(v.rows) == 0 {
		sb.WriteString("  Nothing refused is waiting for review.\n\n")
	} else {
		sb.WriteString("  " + padRight("ID", 6) + padRight("Package", 34) + padRight("Check", 20) +
			padRight("Reqs", 6) + "Last seen\n")
		for i, q := range v.rows {
			cursor := "  "
			if i == v.cursor {
				cursor = "> "
			}
			subject := q.PkgType + "/" + q.PkgName
			if q.PkgVersion != "" {
				subject += "@" + q.PkgVersion
			}
			sb.WriteString(cursor + padRight(fmt.Sprint(q.ID), 6) + padRight(subject, 34) + padRight(q.Check, 20) +
				padRight(fmt.Sprint(q.RequestCount), 6) + q.LastSeen.Local().Format("2006-01-02 15:04") + "\n")
		}
		sel := v.rows[v.cursor]
		sb.WriteString("\n  " + sel.Detail + "\n")
		if sel.Unwaivable != "" {
			sb.WriteString("  Cannot be approved: " + sel.Unwaivable + "\n")
		}
		if sel.Resolution != "" {
			sb.WriteString("  Reopened; it was " + sel.Resolution + "\n")
		}
		sb.WriteByte('\n')
	}
	if v.status != "" {
		sb.WriteString("  " + v.status + "\n\n")
	}
	if v.action != "" {
		fmt.Fprintf(&sb, "Reason to %s: %s_\n[Enter] %s   [Esc] cancel", v.action, v.reason, v.action)
		return sb.String()
	}
	sb.WriteString("[a] approve   [x] dismiss   [r] reload   [Esc] close")
	return sb.String()
}
