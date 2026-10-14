package main

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
)

// bodega queue lists open rows newest first, filters by check, approves under
// the operator's name, refuses known malware naming the check, and dismisses.
func TestQueueCommands(t *testing.T) {
	adbPath := admissionInstall(t, true)
	adb, err := audit.Open(adbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t0 := time.Now().Add(-time.Hour)
	for i, f := range []audit.QueueRefusal{
		{PkgType: manifest.TypeNpm, PkgName: "evil", PkgVersion: "1.0.0", Check: admit.QueueMalware, ClientIP: "10.0.0.9"},
		{PkgType: manifest.TypeNpm, PkgName: "leftpad", PkgVersion: "1.2.0", Check: admit.QueueAllowList, Pattern: "leftpad",
			Identity: "web01", ClientIP: "10.0.0.1"},
	} {
		if err := adb.RecordRefusal(t.Context(), f, t0.Add(time.Duration(i)*time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	_ = adb.Close()
	t.Setenv("SUDO_USER", "alice")

	queue := func(args ...string) (string, error) {
		var runErr error
		out := captureStdout(t, func() {
			cmd := newQueueCmd(&globalFlags{})
			cmd.SetArgs(args)
			cmd.SilenceUsage, cmd.SilenceErrors = true, true
			runErr = cmd.Execute()
		})
		return out, runErr
	}
	out, err := queue("list")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 || !strings.Contains(lines[1], "npm/leftpad@1.2.0") || !strings.Contains(lines[1], "web01@10.0.0.1") {
		t.Fatalf("list =\n%s", out)
	}
	out, err = queue("list", "--check", "malware", "--json")
	var rows []audit.QueueRow
	if err != nil || json.Unmarshal([]byte(out), &rows) != nil || len(rows) != 1 || rows[0].PkgName != "evil" {
		t.Fatalf("list --check malware = %v %s", err, out)
	}
	if _, err := queue("list", "--check", "nope"); err == nil {
		t.Error("an unknown check was accepted")
	}
	evil, leftpad := "1", "2"

	if _, err := queue("approve", evil, "--reason", "please"); !errors.Is(err, admit.ErrQueueUnwaivable) || !strings.Contains(err.Error(), "malware") {
		t.Errorf("approving malware = %v", err)
	}
	if _, err := queue("approve", leftpad); err == nil {
		t.Error("approve without --reason ran")
	}
	out, err = queue("approve", leftpad, "--reason", "INC-1")
	if err != nil || !strings.Contains(out, `added allow-list rule npm package "leftpad"`) {
		t.Fatalf("approve = %v %s", err, out)
	}
	if out, err = queue("dismiss", evil, "--reason", "malicious"); err != nil || !strings.HasPrefix(out, "Dismissed 1") {
		t.Fatalf("dismiss = %v %s", err, out)
	}
	if _, err := queue("dismiss", "77", "--reason", "x"); err == nil || !strings.Contains(err.Error(), "no queue row 77") {
		t.Errorf("dismissing an unknown id = %v", err)
	}
	if out, _ := queue("list"); !strings.Contains(out, "Nothing in the queue.") {
		t.Errorf("list after resolving both =\n%s", out)
	}
	out, _ = queue("list", "--all", "--json")
	if json.Unmarshal([]byte(out), &rows) != nil || len(rows) != 2 || rows[0].ResolvedBy != "alice" {
		t.Errorf("list --all = %s", out)
	}
}
