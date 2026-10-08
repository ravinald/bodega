package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
)

func runAuditServed(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var err error
	out := captureStdout(t, func() {
		cmd := newAuditServedCmd(&globalFlags{})
		cmd.SetArgs(args)
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		err = cmd.Execute()
	})
	return out, err
}

func TestAuditServedPrintsOneIdentitysSet(t *testing.T) {
	dir := t.TempDir()
	adbPath := filepath.Join(dir, "audit.db")
	body := fmt.Sprintf(`{"storage_backend":"local","storage_path":%q,"manifest_dir":%q,"audit_db":%q,"log_dir":%q,"allow_plaintext":true,"apt_codename":"noble"}`,
		filepath.Join(dir, "storage"), filepath.Join(dir, "manifests"), adbPath, dir)
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv(config.EnvConfigFile, cfgPath)

	adb, err := audit.Open(adbPath)
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	digest := strings.Repeat("ab", 32)
	for _, ev := range []audit.Event{
		{EventType: audit.EventServeFetch, PkgType: "npm", PkgName: "widget", PkgVersion: "1.0.0",
			Identity: "build-07", ObjectKey: "packages/npm/widget/widget-1.0.0.tgz", Digest: digest},
		{EventType: audit.EventServeFetch, PkgType: "npm", PkgName: "other", PkgVersion: "2.0.0",
			Identity: "build-08", ObjectKey: "packages/npm/other/other-2.0.0.tgz", Digest: digest},
	} {
		if err := adb.Record(t.Context(), ev); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	_ = adb.Close()

	out, err := runAuditServed(t, "--identity", "build-07", "--since", "7d", "--json")
	if err != nil {
		t.Fatalf("audit served --json: %v", err)
	}
	var rows []audit.ServedArtifact
	if err := json.Unmarshal([]byte(out), &rows); err != nil {
		t.Fatalf("parse %q: %v", out, err)
	}
	want := []audit.ServedArtifact{{PkgType: "npm", PkgName: "widget", PkgVersion: "1.0.0", Digest: digest}}
	if !reflect.DeepEqual(rows, want) {
		t.Errorf("rows = %+v, want %+v", rows, want)
	}

	out, err = runAuditServed(t, "--identity", "build-07")
	if err != nil {
		t.Fatalf("audit served: %v", err)
	}
	if !strings.Contains(out, "widget") || !strings.Contains(out, digest) || strings.Contains(out, "other") {
		t.Errorf("table = %q, want build-07's widget row and digest alone", out)
	}

	if _, err := runAuditServed(t); err == nil || !strings.Contains(err.Error(), "--identity") {
		t.Errorf("no --identity: err = %v, want one naming the flag", err)
	}
	if _, err := runAuditServed(t, "--identity", "build-07", "--since", "soon"); err == nil {
		t.Error("--since soon was accepted")
	}
}
