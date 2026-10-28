package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/clientconf"
	"github.com/ravinald/bodega/internal/config"
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

// The client plan installs the extension only for a server-mode instance
// that sets origins; any other plan writes nothing and keeps the refusal
// --configure osquery has always given.
func TestPlanOsqueryExtension(t *testing.T) {
	server := clientconf.OsqueryPlan{Instance: "osq", Mode: "server"}
	withOrigins := server
	withOrigins.Origins = true
	shipper := clientconf.OsqueryPlan{Instance: "osq-b", Mode: "shipper", Origins: true}

	for name, p := range map[string]clientconf.Plan{
		"no osquery":           {},
		"server, no origins":   {Osquery: []clientconf.OsqueryPlan{server}},
		"shipper with origins": {Osquery: []clientconf.OsqueryPlan{shipper}},
	} {
		root := t.TempDir()
		if _, err := planOsqueryExtension(p, clientconf.OSLinux, "/usr/local/bin/bodega", root); err == nil || !strings.Contains(err.Error(), "setup.sh") {
			t.Errorf("%s: err = %v, want a refusal pointing at setup.sh", name, err)
		}
		if entries, _ := os.ReadDir(root); len(entries) != 0 {
			t.Errorf("%s: wrote %v", name, entries)
		}
	}

	root := t.TempDir()
	autoload := filepath.Join(root, "etc", "osquery", "extensions.load")
	if err := os.MkdirAll(filepath.Dir(autoload), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(autoload, []byte("/opt/other/other.ext"), 0o644); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "usr", "local", "bin", "bodega")
	plan := clientconf.Plan{Osquery: []clientconf.OsqueryPlan{shipper, withOrigins}}
	ext, err := planOsqueryExtension(plan, clientconf.OSLinux, binary, root)
	if err != nil {
		t.Fatal(err)
	}
	if ext.unchanged() {
		t.Fatal("a fresh host reads as already configured")
	}
	if err := ext.apply(); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "usr", "local", "lib", "bodega", "bodega.ext")
	if dest, err := os.Readlink(link); err != nil || dest != binary {
		t.Errorf("link = %q, %v; want it pointing at %s", dest, err, binary)
	}
	if got, _ := os.ReadFile(autoload); string(got) != "/opt/other/other.ext\n/usr/local/lib/bodega/bodega.ext\n" {
		t.Errorf("autoload file = %q, want the operator's line kept and bodega's added", got)
	}
	again, err := planOsqueryExtension(plan, clientconf.OSLinux, binary, root)
	if err != nil || !again.unchanged() {
		t.Errorf("second plan = %+v, %v; want nothing to change", again, err)
	}
	if fb, err := planOsqueryExtension(plan, clientconf.OSFreeBSD, binary, root); err != nil ||
		fb.autoload != filepath.Join(root, "usr", "local", "etc", "osquery", "extensions.load") {
		t.Errorf("freebsd autoload = %+v, %v", fb, err)
	}
}

// osqueryd refuses an extension anyone but root could rewrite, and says so
// only in its own log.
func TestCheckExtensionBinary(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "bodega")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := checkExtensionBinary(bin)
	if os.Geteuid() == 0 {
		if err != nil {
			t.Errorf("root-owned 0755 binary refused: %v", err)
		}
		if err := os.Chmod(bin, 0o775); err != nil {
			t.Fatal(err)
		}
		err = checkExtensionBinary(bin)
	}
	if err == nil || !strings.Contains(err.Error(), "owned by root") {
		t.Errorf("err = %v, want a refusal naming root ownership", err)
	}
}

func TestOsqueryExtensionArgs(t *testing.T) {
	got, ok := osqueryExtensionArgs([]string{"/usr/local/lib/bodega/bodega.ext", "--socket", "/var/osquery/osquery.em", "--timeout", "3", "--interval", "3"})
	want := []string{"/usr/local/lib/bodega/bodega.ext", "osquery", "extension", "--socket", "/var/osquery/osquery.em", "--timeout", "3", "--interval", "3"}
	if !ok || !reflect.DeepEqual(got, want) {
		t.Errorf("args = %v, %v", got, ok)
	}
	if _, ok := osqueryExtensionArgs([]string{"/usr/local/bin/bodega", "osquery", "secret", "list"}); ok {
		t.Error("the bodega binary under its own name ran as the extension")
	}
	t.Setenv(config.EnvConfigFile, filepath.Join(t.TempDir(), "config.json"))
	cmd := newRootCmd()
	cmd.SetArgs(want[1:])
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), "osquery") {
		t.Errorf("extension against no osqueryd: err = %v, want the socket named", err)
	}
}
