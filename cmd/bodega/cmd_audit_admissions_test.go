package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/policy"
)

// admissionInstall writes a config whose npm OSV gate blocks and reads a
// database naming minimist 1.2.0, or with synced false one never synced,
// which makes the gate warn. It returns the audit db path.
func admissionInstall(t *testing.T, synced bool) string {
	t.Helper()
	dir := t.TempDir()
	osvDir := filepath.Join(dir, "osv")
	if err := os.MkdirAll(osvDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if synced {
		export := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			var buf bytes.Buffer
			zw := zip.NewWriter(&buf)
			f, _ := zw.Create("GHSA-test-0001.json")
			_ = json.NewEncoder(f).Encode(map[string]any{
				"id": "GHSA-test-0001",
				"affected": []map[string]any{{
					"package":  map[string]string{"name": "minimist", "ecosystem": "npm"},
					"versions": []string{"1.2.0"},
				}},
			})
			_ = zw.Close()
			_, _ = w.Write(buf.Bytes())
		}))
		t.Cleanup(export.Close)
		db := policy.NewOSVDatabase(osvDir)
		db.ExportBase = export.URL
		if _, err := db.Sync(t.Context(), "npm"); err != nil {
			t.Fatalf("sync: %v", err)
		}
	}
	adbPath := filepath.Join(dir, "audit.db")
	body := fmt.Sprintf(`{
  "storage_backend": "local",
  "storage_path": %q,
  "manifest_dir": %q,
  "audit_db": %q,
  "log_dir": %q,
  "osv_db_dir": %q,
  "allow_plaintext": true,
  "apt_codename": "noble"
}`, filepath.Join(dir, "storage"), filepath.Join(dir, "manifests"), adbPath, dir, osvDir)
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv(config.EnvConfigFile, path)

	adb, err := audit.Open(adbPath)
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	defer adb.Close()
	// The seeded npm age gate dates versions against the public registry.
	if _, err := adb.DeleteAgePolicy(t.Context(), manifest.TypeNpm); err != nil {
		t.Fatalf("delete seeded age policy: %v", err)
	}
	if err := adb.SetOSVPolicy(t.Context(), audit.OSVPolicy{Ecosystem: manifest.TypeNpm, Action: policy.ActionBlock}); err != nil {
		t.Fatalf("set osv policy: %v", err)
	}
	return adbPath
}

// admissionsJSON runs `bodega audit admissions npm minimist --json`.
func admissionsJSON(t *testing.T, args ...string) []audit.Admission {
	t.Helper()
	var rows []audit.Admission
	out := captureStdout(t, func() {
		cmd := newAuditAdmissionsCmd(&globalFlags{})
		cmd.SetArgs(append(args, "--json"))
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		if err := cmd.Execute(); err != nil {
			t.Errorf("audit admissions: %v", err)
		}
	})
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatalf("parse --json output %q: %v", out, err)
	}
	return rows
}

func installDigest(t *testing.T, adbPath string) string {
	t.Helper()
	adb, err := audit.Open(adbPath)
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	defer adb.Close()
	d, err := policy.Digest(t.Context(), adb)
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	return d
}

// TestImportRecordsTheAdmission drives `bodega pkg import` through the
// matrix and reads the result back through `bodega audit admissions`.
func TestImportRecordsTheAdmission(t *testing.T) {
	for _, tc := range []struct {
		name     string
		synced   bool
		version  string
		decision string
		osv      string
	}{
		{"clean_pass", true, "1.2.8", audit.AdmissionAdmitted, audit.CheckPass},
		{"warn", false, "1.2.8", audit.AdmissionAdmitted, audit.CheckWarn},
		{"block", true, "1.2.0", audit.AdmissionPolicyBlocked, audit.CheckBlock},
	} {
		t.Run(tc.name, func(t *testing.T) {
			adbPath := admissionInstall(t, tc.synced)
			file := filepath.Join(t.TempDir(), "minimist.json")
			body := `{"name":"minimist","type":"npm","versions":[{"version":"` + tc.version + `"}]}`
			if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
				t.Fatalf("write manifest: %v", err)
			}
			err := runImport(t, file)
			if blocked := err != nil; blocked != (tc.decision == audit.AdmissionPolicyBlocked) {
				t.Fatalf("pkg import = %v for a %s", err, tc.name)
			}
			rows := admissionsJSON(t, "npm", "minimist", tc.version)
			if len(rows) != 1 {
				t.Fatalf("want one row, got %+v", rows)
			}
			r := rows[0]
			if r.Decision != tc.decision || r.PolicyDigest != installDigest(t, adbPath) || r.Actor != audit.CurrentActor() {
				t.Errorf("row = %+v", r)
			}
			found := false
			for _, c := range r.Checks {
				if c.Check == audit.CheckOSV && c.Status == tc.osv {
					found = true
				}
			}
			if !found {
				t.Errorf("no osv check with status %s: %+v", tc.osv, r.Checks)
			}
		})
	}
}

// TestCreateRecordsTheOperatorsOverride is the y/N prompt's row: the
// allow-list's refusal kept, the answer beside it, the operator as actor.
func TestCreateRecordsTheOperatorsOverride(t *testing.T) {
	adbPath := admissionInstall(t, true)
	adb, err := audit.Open(adbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := adb.InsertPolicy(t.Context(), audit.PolicyInfo{ID: "r1", RegistryType: manifest.TypeNpm, RuleKind: policy.KindPackage, Pattern: "lodash"}); err != nil {
		t.Fatalf("InsertPolicy: %v", err)
	}
	_ = adb.Close()
	cfg, err := loadConfig(&globalFlags{})
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	ve := manifest.VersionEntry{Version: "1.2.8"}
	r := bufio.NewReader(strings.NewReader("y\n"))
	captureStdout(t, func() {
		if err := confirmPolicyOverride(context.Background(), r, &globalFlags{}, cfg, manifest.TypeNpm, "minimist", ve); err != nil {
			t.Errorf("confirmPolicyOverride: %v", err)
		}
	})
	rows := admissionsJSON(t, "npm", "minimist")
	if len(rows) != 1 {
		t.Fatalf("want one row, got %+v", rows)
	}
	got := map[string]string{}
	for _, c := range rows[0].Checks {
		got[c.Check] = c.Status
	}
	if rows[0].Decision != audit.AdmissionAdmitted || got[audit.CheckAllowList] != audit.CheckBlock ||
		got[audit.CheckOverride] != audit.CheckPass || got[audit.CheckOSV] != audit.CheckPass {
		t.Errorf("override row = %+v", rows[0])
	}
	if rows[0].Actor != audit.CurrentActor() {
		t.Errorf("actor = %q, want the operator %q", rows[0].Actor, audit.CurrentActor())
	}
}

// The table is what an operator reads at a terminal: newest first, the one
// check that did not pass spelled out under its row.
func TestAuditAdmissionsTable(t *testing.T) {
	admissionInstall(t, false)
	file := filepath.Join(t.TempDir(), "minimist.json")
	if err := os.WriteFile(file, []byte(`{"name":"minimist","type":"npm","versions":[{"version":"1.2.8"}]}`), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if err := runImport(t, file); err != nil {
		t.Fatalf("pkg import: %v", err)
	}
	out := captureStdout(t, func() {
		cmd := newAuditAdmissionsCmd(&globalFlags{})
		cmd.SetArgs([]string{"npm", "minimist"})
		if err := cmd.Execute(); err != nil {
			t.Errorf("audit admissions: %v", err)
		}
	})
	for _, want := range []string{"1.2.8", "admitted", "osv=warn", "sha256:", "(not pinned)", "osv (warn, action block):", "1 decision(s)"} {
		if !strings.Contains(out, want) {
			t.Errorf("table lacks %q:\n%s", want, out)
		}
	}
	if rows := admissionsJSON(t, "npm", "nothing-here"); rows == nil || len(rows) != 0 {
		t.Errorf("--json for no rows = %v, want []", rows)
	}
}
