package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/audit"
	"github.com/ravinald/bodega/internal/config"
)

const auditChildArgvEnv = "BODEGA_TEST_AUDIT_CHILD_ARGV"

// bypassFixture is a config and audit store holding the serve record every
// test here reads:
//
//	web-01  token-bound; served npm/served@1.0.0
//	web-02  bound to 10.2.0.0/24; served npm/elsewhere@1.0.0
//	web-03  bound to 10.3.0.0/24; one of its addresses was served
//	        npm/moved@1.0.0 under the identity "old-03"
//	(none)  npm/anon@1.0.0, to a request no binding resolved
//
// Bindings are written before any serve, so no serve predates a binding
// except where a test adds one later on purpose.
func bypassFixture(t *testing.T) (dir string, db *audit.DB) {
	t.Helper()
	dir = t.TempDir()
	adbPath := filepath.Join(dir, "audit.db")
	body := fmt.Sprintf(`{"storage_backend":"local","storage_path":%q,"manifest_dir":%q,"audit_db":%q,"log_dir":%q,"allow_plaintext":true,"apt_codename":"noble"}`,
		filepath.Join(dir, "storage"), filepath.Join(dir, "manifests"), adbPath, dir)
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv(config.EnvConfigFile, cfgPath)

	db, err := audit.Open(adbPath)
	if err != nil {
		t.Fatalf("open audit db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for _, b := range []audit.IdentityBinding{
		{Kind: audit.BindToken, Key: "tok-web-01", Identity: "web-01"},
		{Kind: audit.BindCIDR, Key: "10.2.0.0/24", Identity: "web-02"},
		{Kind: audit.BindCIDR, Key: "10.3.0.0/24", Identity: "web-03"},
	} {
		if _, err := db.AddIdentityBinding(t.Context(), b); err != nil {
			t.Fatalf("bind %s: %v", b.Identity, err)
		}
	}
	serve := func(name, identity, ip string) audit.Event {
		return audit.Event{EventType: audit.EventServeFetch, PkgType: "npm", PkgName: name, PkgVersion: "1.0.0",
			Identity: identity, ClientIP: ip, Status: "success",
			ObjectKey: "packages/npm/" + name + "/" + name + "-1.0.0.tgz"}
	}
	for _, ev := range []audit.Event{
		serve("served", "web-01", "10.1.0.5"),
		serve("elsewhere", "web-02", "10.2.0.5"),
		serve("moved", "old-03", "10.3.0.7"),
		serve("anon", "", "10.9.0.9"),
		// A metadata response names no object, so it serves nothing.
		{EventType: audit.EventServeFetch, PkgType: "npm", PkgName: "packument-only", Identity: "web-01"},
	} {
		if err := db.Record(t.Context(), ev); err != nil {
			t.Fatalf("record: %v", err)
		}
	}
	return dir, db
}

// npmInventory writes the JSON pkg convert produces, one version per name,
// with an install time where installed names one.
func npmInventory(t *testing.T, path string, names []string, installed map[string]string) {
	t.Helper()
	var pms []map[string]any
	for _, n := range names {
		ve := map[string]any{"version": "1.0.0", "metadata": map[string]string{"_origin": "web-01"}}
		if at, ok := installed[n]; ok {
			ve["metadata"].(map[string]string)["installed_at"] = at //nolint:forcetypeassert // built two lines up
		}
		pms = append(pms, map[string]any{"config_version": 1, "name": n, "type": "npm", "versions": []any{ve}})
	}
	blob, err := json.Marshal(pms)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, blob, 0o600); err != nil {
		t.Fatal(err)
	}
}

func bypassJSON(t *testing.T, db *audit.DB, req bypassRequest) (bypassReport, int) {
	t.Helper()
	var out bytes.Buffer
	code, err := runAuditBypass(t.Context(), &out, db, req, true)
	if err != nil {
		t.Fatalf("runAuditBypass: %v", err)
	}
	var rep bypassReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("parse %q: %v", out.String(), err)
	}
	return rep, code
}

func classOf(rep bypassReport) map[string]string {
	out := map[string]string{}
	for _, f := range rep.Findings {
		out[f.Name] = f.Class
	}
	return out
}

func TestAuditBypassClassifiesEachInstalledVersion(t *testing.T) {
	dir, db := bypassFixture(t)
	inv := filepath.Join(dir, "web-01.json")
	npmInventory(t, inv, []string{"served", "elsewhere", "nowhere", "anon", "old"},
		map[string]string{"old": "2001-01-01T00:00:00Z", "served": "2001-01-01T00:00:00Z"})

	rep, code := bypassJSON(t, db, bypassRequest{Host: "web-01", Inventory: inv})
	if code != 2 {
		t.Errorf("exit code = %d, want 2 for a host with bypass findings", code)
	}
	want := map[string]string{"elsewhere": bypassServedElsewhere, "nowhere": bypassNeverServed, "old": bypassPredatesAudit}
	if got := classOf(rep); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("findings = %v, want %v", got, want)
	}
	if rep.Served != 1 || rep.Installed != 5 {
		t.Errorf("served %d of %d installed, want 1 of 5 (served@1.0.0 went to web-01 whatever its install time)", rep.Served, rep.Installed)
	}
	if rep.Unattributable[unattributedNoIdentity] != 1 || rep.unattributableTotal() != 1 {
		t.Errorf("unattributable = %v, want anon counted once under %s", rep.Unattributable, unattributedNoIdentity)
	}
	if rep.NoInstallTime != 3 || rep.AuditSince == nil {
		t.Errorf("no_install_time = %d, audit_since = %v; want 3 and the store's first event", rep.NoInstallTime, rep.AuditSince)
	}

	var text bytes.Buffer
	if _, err := runAuditBypass(t.Context(), &text, db, bypassRequest{Host: "web-01", Inventory: inv}, false); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{
		"never_served", "served_elsewhere", "predates_audit", "bodega served elsewhere@1.0.0 to web-02, never to web-01",
		"1 package(s) cannot be attributed and are not counted as bypass: 1 served to a request no identity binding resolved",
		"limit: the audit window starts",
	} {
		if !strings.Contains(text.String(), s) {
			t.Errorf("report lacks %q:\n%s", s, text.String())
		}
	}
	if strings.Contains(text.String(), "anon") {
		t.Errorf("an unattributable package was listed as a finding:\n%s", text.String())
	}
}

func TestAuditBypassImageExclusionClearsTheHost(t *testing.T) {
	dir, db := bypassFixture(t)
	inv := filepath.Join(dir, "web-01.json")
	npmInventory(t, inv, []string{"served", "elsewhere", "nowhere"}, nil)
	image := filepath.Join(dir, "image.json")
	npmInventory(t, image, []string{"elsewhere", "nowhere"}, nil)

	rep, code := bypassJSON(t, db, bypassRequest{Host: "web-01", Inventory: inv, ExcludeImage: image})
	if code != 0 || len(rep.Findings) != 0 {
		t.Errorf("code %d, findings %+v; want 0 and none once the image's packages are excluded", code, rep.Findings)
	}
	if rep.ExcludedImage != 2 || rep.Installed != 1 {
		t.Errorf("excluded %d, installed %d; want 2 and 1", rep.ExcludedImage, rep.Installed)
	}
}

func TestAuditBypassCountsWhatItCannotAttribute(t *testing.T) {
	dir, db := bypassFixture(t)
	inv := filepath.Join(dir, "inv.json")
	npmInventory(t, inv, []string{"moved", "elsewhere"}, nil)

	// web-03's binding covers the address old-03 was served from: the host
	// may be old-03 under its previous binding.
	rep, code := bypassJSON(t, db, bypassRequest{Host: "web-03", Inventory: inv})
	if rep.Unattributable[unattributedBindingChanged] != 1 || classOf(rep)["moved"] != "" {
		t.Errorf("moved: unattributable %v, findings %v; want it counted under %s", rep.Unattributable, classOf(rep), unattributedBindingChanged)
	}
	if classOf(rep)["elsewhere"] != bypassServedElsewhere || code != 2 {
		t.Errorf("elsewhere went to web-02 from web-02's own network: findings %v code %d, want served_elsewhere and 2", classOf(rep), code)
	}

	// A binding written after the serve: the host was something else then.
	if _, err := db.AddIdentityBinding(t.Context(), audit.IdentityBinding{Kind: audit.BindToken, Key: "tok-new", Identity: "web-new"}); err != nil {
		t.Fatal(err)
	}
	rep, code = bypassJSON(t, db, bypassRequest{Host: "web-new", Inventory: inv})
	if rep.Unattributable[unattributedBindingChanged] != 2 || len(rep.Findings) != 0 || code != 0 {
		t.Errorf("web-new: unattributable %v, findings %+v, code %d; want both served before its binding counted and exit 0",
			rep.Unattributable, rep.Findings, code)
	}

	// No binding at all: every request it made carried no identity.
	rep, code = bypassJSON(t, db, bypassRequest{Host: "ghost", Inventory: inv})
	if !rep.Unbound || rep.Unattributable[unattributedHostUnbound] != 2 || code != 0 {
		t.Errorf("ghost: unbound %v, unattributable %v, code %d; want true, 2 under %s, 0", rep.Unbound, rep.Unattributable, code, unattributedHostUnbound)
	}
	var text bytes.Buffer
	if _, err := runAuditBypass(t.Context(), &text, db, bypassRequest{Host: "ghost", Inventory: inv}, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text.String(), "no identity binding names ghost") {
		t.Errorf("unbound host's report does not say so:\n%s", text.String())
	}
}

func TestAuditBypassAnyHost(t *testing.T) {
	dir, db := bypassFixture(t)
	inv := filepath.Join(dir, "web-01.json")
	npmInventory(t, inv, []string{"elsewhere", "anon", "nowhere"}, nil)
	rep, code := bypassJSON(t, db, bypassRequest{Host: "web-01", Inventory: inv, AnyHost: true})
	if rep.Served != 2 || fmt.Sprint(classOf(rep)) != fmt.Sprint(map[string]string{"nowhere": bypassNeverServed}) || code != 2 {
		t.Errorf("--any-host: served %d, findings %v, code %d; want 2 served, nowhere never_served, 2", rep.Served, classOf(rep), code)
	}
}

func TestAuditBypassReadsRawManagerOutput(t *testing.T) {
	dir, db := bypassFixture(t)
	pip := filepath.Join(dir, "pip.json")
	if err := os.WriteFile(pip, []byte(`[{"name":"Requests","version":"2.31.0"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runAuditBypass(t.Context(), &bytes.Buffer{}, db, bypassRequest{Host: "web-01", Inventory: pip}, true); err == nil ||
		!strings.Contains(err.Error(), "--type") {
		t.Errorf("raw pip output with no --type: err = %v, want one naming --type", err)
	}
	rep, _ := bypassJSON(t, db, bypassRequest{Host: "web-01", Inventory: pip, Type: "pypi"})
	if len(rep.Findings) != 1 || rep.Findings[0].Name != "requests" || rep.Findings[0].Class != bypassNeverServed {
		t.Errorf("pip findings = %+v, want requests never_served under its canonical name", rep.Findings)
	}

	dpkg := filepath.Join(dir, "dpkg.txt")
	if err := os.WriteFile(dpkg, []byte("curl\t8.5.0-2ubuntu10\tamd64\tinstall ok installed\tcurl\t978307200\n"+
		"jq\t1.7.1-3\tamd64\tinstall ok installed\tjq\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, _ = bypassJSON(t, db, bypassRequest{Host: "web-01", Inventory: dpkg, Type: "apt"})
	if got := classOf(rep); got["curl"] != bypassPredatesAudit || got["jq"] != bypassNeverServed {
		t.Errorf("dpkg findings = %v, want curl predates_audit from its sixth column and jq never_served", got)
	}

	if _, err := runAuditBypass(t.Context(), &bytes.Buffer{}, db, bypassRequest{Host: "web-01", Inventory: dpkg, Type: "freebsd"}, true); err == nil ||
		!strings.Contains(err.Error(), "repositories") {
		t.Errorf("--type freebsd: err = %v, want one saying the inventory names repositories", err)
	}
}

func TestAuditBypassAllPrintsOneLinePerHost(t *testing.T) {
	dir, db := bypassFixture(t)
	invDir := filepath.Join(dir, "inv")
	if err := os.Mkdir(invDir, 0o700); err != nil {
		t.Fatal(err)
	}
	npmInventory(t, filepath.Join(invDir, "web-01.json"), []string{"served"}, nil)
	npmInventory(t, filepath.Join(invDir, "web-02.json"), []string{"elsewhere", "served", "nowhere"}, nil)

	var out bytes.Buffer
	code, err := runAuditBypass(t.Context(), &out, db, bypassRequest{Dir: invDir}, false)
	if err != nil || code != 2 {
		t.Fatalf("code %d err %v, want 2", code, err)
	}
	for _, s := range []string{
		"web-01: 1 installed, 1 served to it, 0 never_served, 0 served_elsewhere, 0 predates_audit, 0 unattributable",
		"web-02: 3 installed, 1 served to it, 1 never_served, 1 served_elsewhere, 0 predates_audit, 0 unattributable",
		"limit: unattributable packages",
	} {
		if !strings.Contains(out.String(), s) {
			t.Errorf("summary lacks %q:\n%s", s, out.String())
		}
	}

	// A host that cannot be read is named and does not hide another's findings.
	if err := os.WriteFile(filepath.Join(invDir, "web-09.json"), []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	out.Reset()
	code, err = runAuditBypass(t.Context(), &out, db, bypassRequest{Dir: invDir, Stderr: &stderr}, false)
	if err != nil || code != 2 || !strings.Contains(stderr.String(), "web-09") || !strings.Contains(out.String(), "web-09: error:") {
		t.Errorf("code %d err %v stderr %q; want 2 with web-09 named", code, err, stderr.String())
	}

	// With nothing to alert on, the unreadable host is the answer: 1.
	if err := os.Remove(filepath.Join(invDir, "web-02.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := runAuditBypass(t.Context(), &bytes.Buffer{}, db, bypassRequest{Dir: invDir}, false); err == nil {
		t.Error("an unreadable inventory beside a clean host returned no error")
	}
}

// TestAuditBypassExitCodes drives the routed command in a child process, since
// the codes a scheduled job reads are set by os.Exit and by main's error path.
func TestAuditBypassExitCodes(t *testing.T) {
	dir, db := bypassFixture(t)
	_ = db.Close()
	clean := filepath.Join(dir, "clean.json")
	npmInventory(t, clean, []string{"served"}, nil)
	dirty := filepath.Join(dir, "dirty.json")
	npmInventory(t, dirty, []string{"nowhere"}, nil)

	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"clean", []string{"web-01", "--inventory", clean}, 0},
		{"bypass", []string{"web-01", "--inventory", dirty}, 2},
		{"unreadable inventory", []string{"web-01", "--inventory", filepath.Join(dir, "missing.json")}, 1},
		{"no inventory", []string{"web-01"}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args, _ := json.Marshal(append([]string{"audit", "bypass"}, tc.args...))
			cmd := exec.Command(os.Args[0], "-test.run=^TestAuditBypassExitHelper$")
			cmd.Env = append(os.Environ(), auditChildArgvEnv+"="+string(args))
			out, err := cmd.CombinedOutput()
			code := 0
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				code = exit.ExitCode()
			} else if err != nil {
				t.Fatalf("run child: %v", err)
			}
			if code != tc.want {
				t.Errorf("exit %d, want %d; output:\n%s", code, tc.want, out)
			}
		})
	}

	// An audit sink that keeps nothing to read cannot answer.
	cfg := filepath.Join(dir, "jsonl.json")
	body := fmt.Sprintf(`{"storage_backend":"local","storage_path":%q,"manifest_dir":%q,"log_dir":%q,"audit_sink":"jsonl","audit_sink_dsn":%q,"apt_codename":"noble"}`,
		filepath.Join(dir, "storage"), filepath.Join(dir, "manifests"), dir, filepath.Join(dir, "audit.jsonl"))
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	args, _ := json.Marshal([]string{"audit", "bypass", "web-01", "--inventory", clean})
	cmd := exec.Command(os.Args[0], "-test.run=^TestAuditBypassExitHelper$")
	cmd.Env = append(os.Environ(), auditChildArgvEnv+"="+string(args), config.EnvConfigFile+"="+cfg)
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 {
		t.Errorf("jsonl sink: err %v, want exit 1; output:\n%s", err, out)
	}
}

func TestAuditBypassExitHelper(t *testing.T) {
	raw := os.Getenv(auditChildArgvEnv)
	if raw == "" {
		t.Skip("child half of TestAuditBypassExitCodes")
	}
	// The parent names the fixture's config; a child without one would read
	// /etc/bodega/config.json on a host that has bodega installed.
	cfg := os.Getenv(config.EnvConfigFile)
	if cfg == "" {
		t.Fatalf("%s is unset: run this only as the child of TestAuditBypassExitCodes", config.EnvConfigFile)
	}
	t.Setenv(config.EnvConfigFile, cfg)
	var args []string
	if err := json.Unmarshal([]byte(raw), &args); err != nil {
		t.Fatal(err)
	}
	root := newRootCmd()
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		os.Exit(1) //nolint:revive // main's error path, which the parent asserts on
	}
	os.Exit(0) //nolint:revive // so the test harness's own output does not decide the code
}
