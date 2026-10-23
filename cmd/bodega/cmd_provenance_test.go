package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
)

func runRoot(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(args)
	err := root.Execute()
	return out.String(), err
}

func TestPolicyProvenanceSetAndList(t *testing.T) {
	adbPath := admissionInstall(t, false)
	if out, err := runRoot(t, "policy", "provenance", "set", "npm", "block"); err != nil || !strings.Contains(out, "npm upstream provenance policy: block") {
		t.Fatalf("set: %v\n%s", err, out)
	}
	out, err := runRoot(t, "policy", "provenance", "set", "pypi", "block")
	if err != nil || !strings.Contains(out, "block refuses all of them") {
		t.Errorf("block on an uncovered ecosystem should say what it does: %v\n%s", err, out)
	}
	if _, err := runRoot(t, "policy", "provenance", "set", "npm", "allow"); err == nil {
		t.Error("an action outside warn|block|ignore was accepted")
	}
	if _, err := runRoot(t, "policy", "provenance", "set", "quicklisp", "warn"); err == nil {
		t.Error("an unknown ecosystem was accepted")
	}
	out, err = runRoot(t, "policy", "provenance", "list")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"npm", "block", "cargo", "warn (default)"} {
		if !strings.Contains(out, want) {
			t.Errorf("list does not show %q:\n%s", want, out)
		}
	}

	adb, err := audit.Open(adbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer adb.Close()
	if p, err := adb.GetProvenancePolicy(context.Background(), "npm"); err != nil || p.Action != "block" || p.Actor == "" {
		t.Errorf("stored policy = %+v, %v", p, err)
	}
}

// reset clears the pin and records who did it and what the pin held.
func TestPkgTrustShowAndReset(t *testing.T) {
	adbPath := admissionInstall(t, false)
	adb, err := audit.Open(adbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := adb.PinProvenance(context.Background(), audit.ProvenancePin{PkgType: "npm", PkgName: "sigstore",
		SourceRepositoryURI: "https://github.com/sigstore/sigstore-js", BuilderID: "https://github.com/actions/runner/github-hosted",
		PinnedVersion: "3.0.0"}); err != nil {
		t.Fatal(err)
	}
	_ = adb.Close()

	out, err := runRoot(t, "pkg", "trust", "show", "npm", "sigstore")
	if err != nil || !strings.Contains(out, "https://github.com/sigstore/sigstore-js") || !strings.Contains(out, "3.0.0") {
		t.Fatalf("show: %v\n%s", err, out)
	}
	if out, err = runRoot(t, "pkg", "trust", "reset", "npm", "sigstore"); err != nil || !strings.Contains(out, "Cleared the pin") {
		t.Fatalf("reset: %v\n%s", err, out)
	}
	if out, _ = runRoot(t, "pkg", "trust", "show", "npm", "sigstore"); !strings.Contains(out, "has no pin") {
		t.Errorf("show after reset:\n%s", out)
	}

	adb, err = audit.Open(adbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer adb.Close()
	events, err := adb.Query(context.Background(), audit.Filter{EventType: audit.EventPolicy, PkgType: "npm", PkgName: "sigstore"})
	if err != nil || len(events) != 1 {
		t.Fatalf("reset events = %+v, %v", events, err)
	}
	var details map[string]string
	_ = json.Unmarshal([]byte(events[0].Details), &details)
	if events[0].Actor == "" || details["op"] != "trust_reset" || details["source_repository_uri"] != "https://github.com/sigstore/sigstore-js" {
		t.Errorf("reset event = %+v", events[0])
	}
}

func TestServeRefusesAnUnusableTrustedRoot(t *testing.T) {
	dir := t.TempDir()
	junk := filepath.Join(dir, "trusted_root.json")
	if err := os.WriteFile(junk, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"missing": filepath.Join(dir, "absent.json"), "unparsable": junk} {
		t.Run(name, func(t *testing.T) {
			body, _ := json.Marshal(map[string]any{
				"storage_backend": "local", "storage_path": filepath.Join(dir, "storage"),
				"manifest_dir": filepath.Join(dir, "manifests"), "log_dir": dir, "allow_plaintext": true,
				"listen_addr": "127.0.0.1:0", "sigstore_trusted_root": path,
			})
			cfgPath := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(cfgPath, body, 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv(config.EnvConfigFile, cfgPath)
			_, err := runRoot(t, "serve", "--quiet")
			if err == nil || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "sigstore_trusted_root") {
				t.Errorf("serve with %s trusted root: %v", name, err)
			}
		})
	}
}
