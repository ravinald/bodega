package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
)

func osquerySecretEnv(t *testing.T) (dbPath string, pepper func() string) {
	t.Helper()
	dir := t.TempDir()
	pepperPath := filepath.Join(dir, "etc", "pepper")
	prev := audit.DefaultPepperPaths
	audit.DefaultPepperPaths = []string{pepperPath}
	t.Cleanup(func() { audit.DefaultPepperPaths = prev })
	dbPath = filepath.Join(dir, "audit.db")
	loadFrom(t, fmt.Sprintf(`{
  "manifest_dir": %q,
  "audit_db": %q,
  "inventory_sources": {
    "osq":   {"type": "osquery", "enabled": true, "mode": "server"},
    "osq-b": {"type": "osquery", "enabled": true, "mode": "shipper"},
    "bom":   {"type": "cyclonedx", "enabled": true}
  }
}`, filepath.Join(dir, "manifests"), dbPath))
	return dbPath, func() string {
		b, err := os.ReadFile(pepperPath)
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(b))
	}
}

// Requirement 1: the secret is printed once and only its peppered hash is
// stored; list shows everything but the secret; revoke takes the nodes too.
func TestOsquerySecretLifecycle(t *testing.T) {
	dbPath, pepper := osquerySecretEnv(t)
	gf := &globalFlags{}

	create := newOsquerySecretCreateCmd(gf)
	if err := create.Flags().Set("expires", "12h"); err != nil {
		t.Fatal(err)
	}
	var runErr error
	out := captureStdout(t, func() { runErr = create.RunE(create, []string{"osq", "web-01"}) })
	if runErr != nil {
		t.Fatalf("create: %v", runErr)
	}
	secret := regexp.MustCompile(`Secret:\s+(bodega_es_[0-9a-f]{64})`).FindStringSubmatch(out)
	id := regexp.MustCompile(`ID:\s+([0-9a-f]{16})`).FindStringSubmatch(out)
	if secret == nil || id == nil {
		t.Fatalf("create output carries no secret or id:\n%s", out)
	}

	raw, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secret[1]) {
		t.Error("the secret itself reached the database file")
	}
	adb, err := audit.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	got, err := adb.OsquerySecretByHash(ctx, "osq", audit.HashToken(secret[1], pepper()))
	if err != nil || got.ID != id[1] || got.Identity != "web-01" || got.Label != "web-01" || got.ExpiresAt == nil {
		t.Fatalf("stored secret = %+v, %v; want it under its peppered hash with a 12h expiry", got, err)
	}
	if d := time.Until(*got.ExpiresAt); d < 11*time.Hour || d > 13*time.Hour {
		t.Errorf("expiry %s from now, want about 12h", d)
	}
	if err := adb.EnrollOsqueryNode(ctx, audit.OsqueryNode{Source: "osq", KeySHA256: "k1", SecretID: got.ID, Identity: "web-01"}); err != nil {
		t.Fatal(err)
	}
	_ = adb.Close()

	list := newOsquerySecretListCmd(gf)
	out = captureStdout(t, func() { runErr = list.RunE(list, nil) })
	if runErr != nil {
		t.Fatal(runErr)
	}
	for _, want := range []string{"LABEL", "IDENTITY", "CREATED", "EXPIRES", id[1], "web-01"} {
		if !strings.Contains(out, want) {
			t.Errorf("list lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, secret[1]) || strings.Contains(out, "bodega_es_") {
		t.Errorf("list printed the secret:\n%s", out)
	}
	if err := list.Flags().Set("json", "true"); err != nil {
		t.Fatal(err)
	}
	out = captureStdout(t, func() { runErr = list.RunE(list, nil) })
	var rows []audit.OsquerySecret
	if err := json.Unmarshal([]byte(out), &rows); err != nil || len(rows) != 1 || rows[0].Nodes != 1 {
		t.Errorf("list --json = %s (%v)", out, err)
	}

	revoke := newOsquerySecretRevokeCmd(gf)
	out = captureStdout(t, func() { runErr = revoke.RunE(revoke, []string{id[1]}) })
	if runErr != nil || !strings.Contains(out, "1 node key") {
		t.Fatalf("revoke: %v\n%s", runErr, out)
	}
	adb, err = audit.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer adb.Close()
	if _, found, _ := adb.OsqueryNodeByKey(ctx, "osq", "k1"); found {
		t.Error("revoke left the node enrolled with the secret")
	}
	if err := revoke.RunE(revoke, []string{id[1]}); err == nil || !strings.Contains(err.Error(), "secret list") {
		t.Errorf("revoking twice: %v", err)
	}
}

func TestOsquerySecretCreateRefusesNonServerInstances(t *testing.T) {
	osquerySecretEnv(t)
	for instance, want := range map[string]string{
		"osq-b": "shipper mode",
		"bom":   "only an osquery source",
		"nope":  "no inventory source named",
	} {
		create := newOsquerySecretCreateCmd(&globalFlags{})
		err := create.RunE(create, []string{instance, "web-01"})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want one saying %q", instance, err, want)
		}
	}
	create := newOsquerySecretCreateCmd(&globalFlags{})
	_ = create.Flags().Set("expires", "soon")
	if err := create.RunE(create, []string{"osq", "web-01"}); err == nil || !strings.Contains(err.Error(), "--expires") {
		t.Errorf("bad --expires: %v", err)
	}
}
