package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/integration"
)

// foreignConfig is a config file whose keys the integration commands do not
// own, written the way an operator might: a one-line list, a comment block,
// odd spacing inside a value.
const foreignConfig = `{
  "_comment_acl": "deny_list is seeded into the audit DB on first start",
  "deny_list": ["10.0.0.0/8",   "192.168.0.0/16"],
  "storage_backend": "local",
  "storage_path": %q,
  "manifest_dir": %q,
  "audit_db": %q,

  "log_dir": %q,
  "future_key": {"nested": [1, 2,3], "kept":    true}
}
`

func integrationFixture(t *testing.T) (cfgPath string, original []byte) {
	t.Helper()
	dir := t.TempDir()
	cfgPath = filepath.Join(dir, "config.json")
	body := []byte(strings.TrimSpace(fmtConfig(foreignConfig, filepath.Join(dir, "storage"), filepath.Join(dir, "manifests"),
		filepath.Join(dir, "audit.db"), dir)) + "\n")
	if err := os.WriteFile(cfgPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(config.EnvConfigFile, cfgPath)
	return cfgPath, body
}

func fmtConfig(format string, args ...any) string {
	b, _ := json.Marshal(args[0])
	out := strings.Replace(format, "%q", string(b), 1)
	for _, a := range args[1:] {
		b, _ := json.Marshal(a)
		out = strings.Replace(out, "%q", string(b), 1)
	}
	return out
}

func runIntegration(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	cmd := newIntegrationCmd(&globalFlags{})
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetArgs(args)
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	err := cmd.Execute()
	return out.String(), err
}

// withoutIntegrations is the file with its integrations key and the line
// separator before it removed, which is what every other key's bytes must
// still equal.
func withoutIntegrations(t *testing.T, data []byte) string {
	t.Helper()
	s := string(data)
	i := strings.Index(s, ",\n  \"integrations\":")
	if i < 0 {
		return s
	}
	return s[:i] + "\n}\n"
}

// Every edit verb writes the integrations key and leaves every other key's
// bytes, order and blank lines as the operator wrote them.
func TestIntegrationEditsKeepForeignKeys(t *testing.T) {
	cfgPath, original := integrationFixture(t)
	steps := [][]string{
		{"add", "aikido", "malware-list", "--set", "refresh_interval=12h"},
		{"set", "aikido", "timeout=30s", "url=https://mirror.example.test/lists/"},
		{"enable", "aikido"},
		{"disable", "aikido"},
		{"add", "second", "malware-list"},
		{"set", "aikido", "timeout="},
	}
	for _, args := range steps {
		if out, err := runIntegration(t, "", args...); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
		got, _ := os.ReadFile(cfgPath)
		if withoutIntegrations(t, got) != string(original) {
			t.Fatalf("after %v the other keys changed:\n--- before\n%s--- after\n%s", args, original, got)
		}
	}
	entries, err := integration.FileEntries()
	if err != nil {
		t.Fatal(err)
	}
	a := entries["aikido"]
	if a["refresh_interval"] != "12h" || a["url"] != "https://mirror.example.test/lists/" || a["enabled"] != false {
		t.Errorf("aikido = %v", a)
	}
	if _, set := a["timeout"]; set {
		t.Errorf("an empty value left timeout set: %v", a)
	}
	// The file still loads, through the same validator.
	if _, err := config.Load("", "", "", "", true, false); err != nil {
		t.Errorf("the edited file no longer loads: %v", err)
	}

	if _, err := runIntegration(t, "", "remove", "second"); err != nil {
		t.Fatal(err)
	}
	if _, err := runIntegration(t, "", "remove", "aikido"); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(cfgPath)
	if string(got) != string(original) {
		t.Errorf("removing every instance did not restore the file:\n%s", got)
	}
}

// An edit the validator refuses writes nothing.
func TestIntegrationEditsRefuseInvalid(t *testing.T) {
	cfgPath, original := integrationFixture(t)
	refused := map[string][]string{
		"unknown type":   {"add", "x", "no-such-type"},
		"unknown key":    {"add", "x", "malware-list", "--set", "colour=red"},
		"wrong kind":     {"add", "x", "malware-list", "--set", "refresh_interval=often"},
		"out of range":   {"add", "x", "malware-list", "--set", "refresh_interval=1m"},
		"bad url":        {"add", "x", "malware-list", "--set", "url=ftp://x/"},
		"bad name":       {"add", "X.Y", "malware-list"},
		"missing":        {"set", "nobody", "url=https://x/"},
		"no secret here": {"secret", "x", "url"},
	}
	for name, args := range refused {
		if out, err := runIntegration(t, "sk", args...); err == nil {
			t.Errorf("%s: %v succeeded:\n%s", name, args, out)
		}
		if got, _ := os.ReadFile(cfgPath); string(got) != string(original) {
			t.Fatalf("%s: a refused edit changed the file:\n%s", name, got)
		}
	}
	out, err := runIntegration(t, "", "add", "x", "malware-list", "--set", "refresh_interval=1m")
	if err == nil || !strings.Contains(err.Error(), "integrations.x.refresh_interval: want a duration") {
		t.Errorf("error does not name the instance and key: %v %s", err, out)
	}
}

// A hand-written entry reads back through show and list, and show --json
// redacts anything secret-looking.
func TestIntegrationShowReadsHandEdits(t *testing.T) {
	cfgPath, original := integrationFixture(t)
	hand := strings.Replace(string(original), "\n}\n", `,
  "integrations": {"handmade": {"type": "malware-list", "enabled": true, "refresh_interval": "1d"}}
}
`, 1)
	if err := os.WriteFile(cfgPath, []byte(hand), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runIntegration(t, "", "show", "handmade")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"type:     malware-list", "enabled:  yes", "refresh_interval  1d", "config file",
		"url               https://malware-list.aikido.dev/  default", "sends:    Nothing per package"} {
		if !strings.Contains(out, want) {
			t.Errorf("show lacks %q:\n%s", want, out)
		}
	}
	out, err = runIntegration(t, "", "list", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []integrationRow
	if err := json.Unmarshal([]byte(out), &rows); err != nil || len(rows) != 1 || !rows[0].Enabled || !rows[0].Valid {
		t.Errorf("list --json = %s (%v)", out, err)
	}

	// A literal secret in a hand edit: list says why it is invalid, and
	// show --json never prints the value.
	bad := strings.Replace(hand, `"refresh_interval": "1d"`, `"refresh_interval": "1d", "api_token": "sk-live-999"`, 1)
	if err := os.WriteFile(cfgPath, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"show", "handmade", "--json"}, {"show", "handmade"}, {"list", "--json"}, {"list"}} {
		out, _ := runIntegration(t, "", args...)
		if strings.Contains(out, "sk-live-999") {
			t.Errorf("%v printed the secret:\n%s", args, out)
		}
	}
	if _, err := config.Load("", "", "", "", true, false); err == nil || !strings.Contains(err.Error(), "integrations.handmade.api_token") {
		t.Errorf("Load accepted a literal secret: %v", err)
	}
}

func TestPolicyIntegrationSetAndList(t *testing.T) {
	integrationFixture(t)
	if _, err := runIntegration(t, "", "add", "aikido", "malware-list"); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) (string, error) {
		cmd := newPolicyIntegrationCmd(&globalFlags{})
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetArgs(args)
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		err := cmd.Execute()
		return out.String(), err
	}
	out, err := run("list")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "aikido    npm        block   malware-list default") {
		t.Errorf("default not listed:\n%s", out)
	}
	if _, err := run("set", "aikido", "npm", "warn"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]string{{"set", "aikido", "cargo", "warn"}, {"set", "aikido", "npm", "pass"}, {"set", "nobody", "npm", "warn"}} {
		if _, err := run(bad...); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
	out, _ = run("list")
	if !strings.Contains(out, "aikido    npm        warn    set by") || !strings.Contains(out, "aikido    pypi       block   malware-list default") {
		t.Errorf("after set:\n%s", out)
	}
	cfg, err := config.Load("", "", "", "", true, false)
	if err != nil {
		t.Fatal(err)
	}
	adb, err := audit.Open(cfg.AuditDB)
	if err != nil {
		t.Fatal(err)
	}
	defer adb.Close()
	if p, err := adb.GetIntegrationPolicy(t.Context(), "aikido", "npm"); err != nil || p.Action != "warn" {
		t.Errorf("row = %+v, %v", p, err)
	}
}

// The shipped-types table in docs/usage.md is the registry's, rendered.
func TestUsageIntegrationTableMatchesRegistry(t *testing.T) {
	raw, err := os.ReadFile("../../docs/usage.md")
	if err != nil {
		t.Fatal(err)
	}
	const begin, end = "<!-- integration-types:begin -->", "<!-- integration-types:end -->"
	doc := string(raw)
	i, j := strings.Index(doc, begin), strings.Index(doc, end)
	if i < 0 || j < i {
		t.Fatalf("docs/usage.md has no %s ... %s block", begin, end)
	}
	got := strings.TrimSpace(doc[i+len(begin) : j])
	want := strings.TrimSpace(integration.DocTable())
	if got != want {
		t.Errorf("docs/usage.md's integration table disagrees with the registry; replace it with:\n%s", want)
	}
}
