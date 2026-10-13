package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/admit"
	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// revetInstall is rescanInstall with an npm OSV gate set to block, the
// seeded age gate removed (it reads the public registry), each version
// admitted a month ago, and revet_on_block set as given.
func revetInstall(t *testing.T, onBlock string, versions ...manifest.VersionEntry) string {
	t.Helper()
	root := rescanInstall(t, versions...)
	cfgPath := os.Getenv("BODEGA_CONFIG_FILE")
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg["revet_on_block"] = onBlock
	blob, _ := json.Marshal(cfg)
	if err := os.WriteFile(cfgPath, blob, 0o600); err != nil {
		t.Fatal(err)
	}

	adb, err := audit.Open(filepath.Join(root, "logs", "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer adb.Close()
	ctx := context.Background()
	if _, err := adb.DeleteAgePolicy(ctx, manifest.TypeNpm); err != nil {
		t.Fatal(err)
	}
	if err := adb.SetOSVPolicy(ctx, audit.OSVPolicy{Ecosystem: manifest.TypeNpm, Action: policy.ActionBlock}); err != nil {
		t.Fatal(err)
	}
	for _, ve := range versions {
		if err := adb.RecordAdmission(ctx, audit.Admission{
			PkgType: manifest.TypeNpm, PkgName: "minimist", PkgVersion: ve.Version,
			Decision: audit.AdmissionAdmitted, Checks: audit.NotEvaluatedChecks("seeded"),
			DecidedAt: time.Now().Add(-30 * 24 * time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func runRevet(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	outR, outW, _ := os.Pipe()
	errR, errW, _ := os.Pipe()
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = outW, errW

	cmd := newPolicyRevetCmd(&globalFlags{})
	cmd.SetArgs(args)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	err = cmd.Execute()

	os.Stdout, os.Stderr = oldOut, oldErr
	_ = outW.Close()
	_ = errW.Close()
	o, _ := io.ReadAll(outR)
	e, _ := io.ReadAll(errR)
	return string(o), string(e), err
}

// The composed path: an advisory synced after admission, the command, the
// new row in the audit store and the hide on disk. 1.2.8 is outside the
// advisory and stays admitted and served.
func TestRevetCommandHidesWhatAnAdvisoryNowBlocks(t *testing.T) {
	root := revetInstall(t, "hide", manifest.VersionEntry{Version: "1.2.5"}, manifest.VersionEntry{Version: "1.2.8"})
	syncInto(t, root, advisory("GHSA-late", "minimist", "1.2.4", "1.2.6"))

	stdout, stderr, err := runRevet(t, "--type", "npm", "--name", "minimist")
	if err != nil {
		t.Fatalf("revet: %v\n%s", err, stderr)
	}
	if !strings.Contains(stderr, "2 version(s): 1 admitted, 1 refused (1 hidden, 0 frozen)") {
		t.Errorf("summary = %q", stderr)
	}
	if !strings.Contains(stdout, "GHSA-late") {
		t.Errorf("the table must name the failing advisory: %q", stdout)
	}
	if !reloadVersion(t, root, "1.2.5").Hidden {
		t.Error("1.2.5 not hidden on disk")
	}
	if reloadVersion(t, root, "1.2.8").Hidden {
		t.Error("1.2.8 hidden though no advisory names it")
	}
	hides := auditEvents(t, root, audit.Filter{EventType: audit.EventHide})
	if len(hides) != 1 || hides[0].Actor != admit.RevetActor || !strings.Contains(hides[0].Details, "GHSA-late") {
		t.Errorf("hide events = %+v", hides)
	}

	adb, err := audit.Open(filepath.Join(root, "logs", "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer adb.Close()
	rows, err := adb.Admissions(context.Background(), audit.AdmissionFilter{PkgType: manifest.TypeNpm, PkgName: "minimist", PkgVersion: "1.2.5"})
	if err != nil || len(rows) != 2 {
		t.Fatalf("1.2.5 rows = %d (%v), want the admission and the re-vet", len(rows), err)
	}
	if rows[0].Decision != audit.AdmissionPolicyBlocked || rows[0].Actor != admit.RevetActor || rows[1].Decision != audit.AdmissionAdmitted {
		t.Errorf("rows = %s by %s, then %s", rows[0].Decision, rows[0].Actor, rows[1].Decision)
	}
}

// A frozen version the re-vet refuses stays served and fails the run.
func TestRevetCommandFrozenFailsTheRun(t *testing.T) {
	root := revetInstall(t, "hide", manifest.VersionEntry{Version: "1.2.5", Frozen: true})
	syncInto(t, root, advisory("GHSA-late", "minimist", "1.2.4", "1.2.6"))
	_, stderr, err := runRevet(t)
	if err == nil || !strings.Contains(err.Error(), "frozen") {
		t.Fatalf("err = %v, want the frozen refusal to fail the run\n%s", err, stderr)
	}
	if reloadVersion(t, root, "1.2.5").Hidden {
		t.Error("a frozen version was hidden")
	}
}

func TestRevetCommandRejectsABadOlderThan(t *testing.T) {
	revetInstall(t, "report", manifest.VersionEntry{Version: "1.2.5"})
	if _, _, err := runRevet(t, "--older-than", "soon"); err == nil {
		t.Error("--older-than soon was accepted")
	}
}
