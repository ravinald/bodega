package clientconf

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func digest(b string) string {
	sum := sha256.Sum256([]byte(b))
	return hex.EncodeToString(sum[:])
}

func testPlan() Plan {
	return Plan{Records: []PlanRecord{
		{System: "apt", Action: PlanInstall, Path: "/etc/apt/sources.list.d/bodega.sources", SHA256: digest("stanza\n")},
		{System: "apt", Action: PlanInstall, Path: "/etc/apt/keyrings/bodega.gpg", SHA256: digest("ring")},
		{System: "npm", Action: PlanRefuse, Reason: "profile web closes npm"},
		{System: "pypi", Action: PlanInstall, Path: "/etc/pip.conf", SHA256: digest("[global]\n")},
	}}
}

func TestPlanSelectNarrowsAndNamesWhatThePlanLists(t *testing.T) {
	p := testPlan()
	if got, err := p.Select(nil); err != nil || len(got) != len(p.Records) {
		t.Errorf("Select(nil) = %d records, %v; want every record", len(got), err)
	}
	got, err := p.Select([]string{"apt"})
	if err != nil || len(got) != 2 || got[0].System != "apt" || got[1].System != "apt" {
		t.Errorf("Select(apt) = %+v, %v; want both apt records", got, err)
	}
	_, err = p.Select([]string{"apt", "nuget"})
	if err == nil || !strings.Contains(err.Error(), `"nuget"`) || !strings.Contains(err.Error(), "apt, npm, pypi") {
		t.Errorf("Select(nuget) = %v, want an error naming nuget and the plan's list", err)
	}
	_, err = p.Select([]string{"npm", "pypi"})
	if err == nil || !strings.Contains(err.Error(), "profile web closes npm") {
		t.Errorf("Select(npm) = %v, want the refusal's reason", err)
	}
}

func TestNewChangeRefusesADigestMismatchNamingBoth(t *testing.T) {
	rec := PlanRecord{System: "pypi", Action: PlanInstall, Path: "/nonexistent/pip.conf", URL: "https://b/client/pypi", SHA256: digest("[global]\n")}
	_, err := NewChange(rec, []byte("[global]\nindex-url = https://evil/\n"), "")
	if err == nil {
		t.Fatal("NewChange accepted bytes the plan's digest does not describe")
	}
	for _, want := range []string{"pypi", rec.SHA256, digest("[global]\nindex-url = https://evil/\n"), "nothing on this host was changed", "Re-run"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("mismatch error lacks %q:\n%v", want, err)
		}
	}
}

func TestTargetPathResolvesHomeAndRefusesRelative(t *testing.T) {
	if got, err := TargetPath("~/.npmrc", "/home/op"); err != nil || got != "/home/op/.npmrc" {
		t.Errorf("TargetPath(~/.npmrc) = %q, %v", got, err)
	}
	if _, err := TargetPath("~/.npmrc", ""); err == nil {
		t.Error("TargetPath(~/.npmrc) with no home resolved anyway")
	}
	if _, err := TargetPath("etc/pip.conf", "/home/op"); err == nil {
		t.Error("TargetPath accepted a relative path")
	}
}

// Apply backs up what it replaces, creates what is missing, leaves an
// unchanged file alone, and writes a system's companion before its own file.
func TestApplyBacksUpWritesAndSkipsUnchanged(t *testing.T) {
	home := t.TempDir()
	mk := func(path, content string) PlanRecord {
		return PlanRecord{System: "x", Action: PlanInstall, Path: path, SHA256: digest(content)}
	}
	if err := os.WriteFile(filepath.Join(home, "replaced"), []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "same"), []byte("same\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var changes []Change
	for _, f := range []struct{ path, content string }{
		{"~/replaced", "new\n"},
		{"~/dir/created", "created\n"},
		{"~/same", "same\n"},
	} {
		c, err := NewChange(mk(f.path, f.content), []byte(f.content), home)
		if err != nil {
			t.Fatalf("NewChange(%s): %v", f.path, err)
		}
		changes = append(changes, c)
	}
	if !changes[2].Unchanged() || changes[0].Unchanged() {
		t.Fatalf("Unchanged = %v %v %v, want false false true", changes[0].Unchanged(), changes[1].Unchanged(), changes[2].Unchanged())
	}
	d, err := changes[0].Diff()
	if err != nil || !strings.Contains(d, "-old") || !strings.Contains(d, "+new") {
		t.Errorf("Diff = %q, %v; want a unified diff from old to new", d, err)
	}

	applied, err := Apply(changes, ".bodega-test")
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(applied) != 2 || applied[0].Target != filepath.Join(home, "dir/created") {
		t.Errorf("applied = %+v, want two writes, last planned first", applied)
	}
	for path, want := range map[string]string{
		"replaced":             "new\n",
		"replaced.bodega-test": "old\n",
		"dir/created":          "created\n",
		"same":                 "same\n",
	} {
		got, err := os.ReadFile(filepath.Join(home, path))
		if err != nil || string(got) != want {
			t.Errorf("%s = %q, %v; want %q", path, got, err, want)
		}
	}
	if info, _ := os.Stat(filepath.Join(home, "replaced")); info.Mode().Perm() != 0o600 {
		t.Errorf("replaced file mode = %v, want its own 0600 kept", info.Mode().Perm())
	}
	if _, err := os.Stat(filepath.Join(home, "same.bodega-test")); err == nil {
		t.Error("an unchanged file was backed up")
	}
}

// A target this process cannot write stops the run before the first write,
// so no host ends up with half a plan.
func TestApplyWritesNothingWhenOneTargetIsUnwritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes everywhere")
	}
	home := t.TempDir()
	locked := filepath.Join(home, "locked")
	if err := os.Mkdir(locked, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	a, _ := NewChange(PlanRecord{System: "a", Path: "~/ok", SHA256: digest("a")}, []byte("a"), home)
	b, _ := NewChange(PlanRecord{System: "b", Path: "~/locked/f", SHA256: digest("b")}, []byte("b"), home)
	_, err := Apply([]Change{a, b}, ".bodega-test")
	if err == nil || !strings.Contains(err.Error(), "Nothing was written") {
		t.Fatalf("Apply = %v, want a refusal before any write", err)
	}
	if _, err := os.Stat(filepath.Join(home, "ok")); err == nil {
		t.Error("the writable target was written before the unwritable one was refused")
	}
}

// An apply over ~/.npmrc or repositories.yaml keeps the credential `bodega
// doctor --write-credentials` put there, lands on the bytes that writer would
// produce over the planned file, and a second run finds nothing to change.
func TestApplyKeepsTheCredentialTheWriterPlaced(t *testing.T) {
	const base = "https://h"
	fence := func(body string) string { return CredentialBegin + "\n" + body + "\n" + CredentialEnd + "\n" }
	helmCred := HelmRepository(base, "username: bodega", "password: bodega_ak_x", "insecure_skip_tls_verify: false")
	cases := []struct {
		name, system, planned, existing, want string
	}{
		{
			name: "npm fenced", system: "npm", planned: Npm(base).Content,
			existing: "registry=https://registry.npmjs.org/\n" + fence("//h/npm/:_authToken=bodega_ak_x"),
			want:     Npm(base).Content + fence("//h/npm/:_authToken=bodega_ak_x"),
		},
		{
			name: "npm unfenced after npm rewrote it", system: "npm", planned: Npm(base).Content,
			existing: "color=false\n//h/npm/:_authToken=bodega_ak_x\n",
			want:     Npm(base).Content + "//h/npm/:_authToken=bodega_ak_x\n",
		},
		{
			name: "helm fenced", system: "helm", planned: Helm(base).Content,
			existing: HelmDocument("- name: other\n  url: https://o\n" + fence(strings.TrimSuffix(helmCred, "\n"))),
			want:     HelmDocument(fence(strings.TrimSuffix(helmCred, "\n"))),
		},
		{
			name: "helm as helm serializes it", system: "helm", planned: Helm(base).Content,
			existing: "apiVersion: \"\"\nrepositories:\n- caFile: \"\"\n  name: bodega\n  password: bodega_ak_x\n  url: https://h/helm\n  username: bodega\n",
			want:     HelmDocument("- caFile: \"\"\n  name: bodega\n  password: bodega_ak_x\n  url: https://h/helm\n  username: bodega\n"),
		},
		{
			name: "helm entry with no password", system: "helm", planned: Helm(base).Content,
			existing: HelmDocument("- name: bodega\n  url: https://old/helm\n"),
			want:     Helm(base).Content,
		},
		{
			name: "another system keeps nothing", system: "gomod", planned: "GOPROXY=https://h/go\n",
			existing: "//h/npm/:_authToken=bodega_ak_x\n",
			want:     "GOPROXY=https://h/go\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			path := filepath.Join(home, "f")
			if err := os.WriteFile(path, []byte(tc.existing), 0o600); err != nil {
				t.Fatal(err)
			}
			rec := PlanRecord{System: tc.system, Action: PlanInstall, Path: path, SHA256: digest(tc.planned)}
			c, err := NewChange(rec, []byte(tc.planned), home)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Apply([]Change{c}, ".bak"); err != nil {
				t.Fatal(err)
			}
			got, _ := os.ReadFile(path)
			if string(got) != tc.want {
				t.Fatalf("after apply:\n%s\nwant:\n%s", got, tc.want)
			}
			again, err := NewChange(rec, []byte(tc.planned), home)
			if err != nil {
				t.Fatal(err)
			}
			if !again.Unchanged() {
				t.Errorf("a second apply would rewrite the file:\n%s", again.New)
			}
			if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
				t.Errorf("mode %v after apply, want the 0600 the credential was written with", info.Mode().Perm())
			}
		})
	}
}

// Diff prints no secret from either side: not the token being kept, not one
// being dropped, not a password inside a URL.
func TestDiffPrintsNoCredential(t *testing.T) {
	home := t.TempDir()
	cases := []struct{ system, existing, planned string }{
		{"npm", "//h/npm/:_authToken=bodega_ak_kept\n//other/:_authToken=bodega_ak_gone\n_auth = bodega_ak_b64\n", Npm("https://h").Content},
		{"helm", HelmDocument("- name: bodega\n  url: https://h/helm\n  password: bodega_ak_kept\n- name: x\n  password: 'bodega_ak_gone'\n"), Helm("https://h").Content},
		{"pypi", "[global]\nindex-url = https://op:bodega_ak_url@pypi.internal/simple/\n", Pip("https://h").Content},
		{"pypi", "", "[global]\nindex-url = https://op:bodega_ak_new@h/pypi/simple/\n"},
	}
	for _, tc := range cases {
		path := filepath.Join(home, tc.system)
		_ = os.Remove(path)
		if tc.existing != "" {
			if err := os.WriteFile(path, []byte(tc.existing), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		c, err := NewChange(PlanRecord{System: tc.system, Action: PlanInstall, Path: path, SHA256: digest(tc.planned)}, []byte(tc.planned), home)
		if err != nil {
			t.Fatal(err)
		}
		d, err := c.Diff()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(d, "bodega_ak_") {
			t.Errorf("%s: diff prints a token:\n%s", tc.system, d)
		}
		if !strings.Contains(d, Redacted) {
			t.Errorf("%s: diff shows no %s where the secret was:\n%s", tc.system, Redacted, d)
		}
	}
}

// The osquery system needs a package, a secret and a running daemon, none of
// which a file-only apply provides, so it is left out of an empty selection
// and refused by name.
func TestSelectKeepsOsqueryOutOfAFileOnlyApply(t *testing.T) {
	p := Plan{Records: []PlanRecord{
		{System: "pypi", Action: PlanInstall, Path: "/etc/pip.conf"},
		{System: SystemOsquery, Action: PlanInstall, Path: OsqueryFlagsPaths[OSLinux]},
	}}
	got, err := p.Select(nil)
	if err != nil || len(got) != 1 || got[0].System != "pypi" {
		t.Errorf("Select(nil) = %+v, %v; want pypi alone", got, err)
	}
	if _, err := p.Select([]string{SystemOsquery}); err == nil || !strings.Contains(err.Error(), "setup.sh") {
		t.Errorf("Select(osquery) = %v, want a refusal naming setup.sh", err)
	}
}

// The plan lists the flags bodega owns as set, the two that stay the
// operator's as default, and adds tls to logger_plugin rather than writing it
// alone. --tls_server_certs names a CA bundle, which only a TLS server needs.
func TestOsqueryFlagsNameCertsOnlyOverTLS(t *testing.T) {
	src := OsqueryPlan{Instance: "osq", Mode: "server", Endpoint: "https://b.example:8443/api/v1/inventory/sources/osq", Interval: 600}
	ep := "/api/v1/inventory/sources/osq"
	cases := []struct {
		base, goos string
		certs      string
		secret     string
	}{
		{"http://b.example:8443", OSLinux, "", "/etc/osquery/bodega.secret"},
		{"http://b.example:8443", OSFreeBSD, "", "/usr/local/etc/osquery/bodega.secret"},
		{"https://b.example:8443", OSLinux, "/etc/ssl/certs/ca-certificates.crt", "/etc/osquery/bodega.secret"},
		{"https://b.example:8443", OSFreeBSD, "/etc/ssl/cert.pem", "/usr/local/etc/osquery/bodega.secret"},
	}
	for _, c := range cases {
		want := []OsqueryFlag{{OsqueryFlagSet, "tls_hostname", "b.example:8443"}}
		if c.certs != "" {
			want = append(want, OsqueryFlag{OsqueryFlagSet, "tls_server_certs", c.certs})
		}
		want = append(want,
			OsqueryFlag{OsqueryFlagSet, "enroll_secret_path", c.secret},
			OsqueryFlag{OsqueryFlagSet, "enroll_tls_endpoint", ep + "/enroll"},
			OsqueryFlag{OsqueryFlagSet, "config_plugin", "tls"},
			OsqueryFlag{OsqueryFlagSet, "config_tls_endpoint", ep + "/config"},
			OsqueryFlag{OsqueryFlagSet, "config_refresh", "600"},
			OsqueryFlag{OsqueryFlagDefault, "host_identifier", "uuid"},
			OsqueryFlag{OsqueryFlagDefault, "logger_plugin", "filesystem,tls"},
			OsqueryFlag{OsqueryFlagInclude, "logger_plugin", "tls"},
			OsqueryFlag{OsqueryFlagSet, "logger_tls_endpoint", ep + "/log"},
		)
		if got := OsqueryFlags(c.base, src, c.goos); !reflect.DeepEqual(got, want) {
			t.Errorf("%s on %s:\n got  %+v\n want %+v", c.base, c.goos, got, want)
		}
	}

	files := Osquery("https://b.example:8443", src)
	if len(files) != 2 {
		t.Fatalf("Osquery = %d files, want one per OS", len(files))
	}
	for _, f := range files {
		goos := OSLinux
		if f.Path(OSLinux) == "" {
			goos = OSFreeBSD
		}
		from := map[string]string{OSLinux: "from\tFLAG_FILE\t/etc/default/osqueryd\n", OSFreeBSD: "from\tosqueryd_flagfile\tsysrc\n"}[goos]
		if f.Path(goos) != OsqueryFlagsPaths[goos] || !strings.HasPrefix(f.Content, from) ||
			!strings.Contains(f.Content, "\ninclude\tlogger_plugin\ttls\n") || strings.Contains(f.Content, "--") {
			t.Errorf("%s plan file at %s:\n%s", goos, f.Path(goos), f.Content)
		}
	}
	if OsqueryFlagsPaths[OSFreeBSD] != "/usr/local/etc/osquery/osquery.flags" {
		t.Errorf("FreeBSD flags path = %s, want the sysutils/osquery rc script's default", OsqueryFlagsPaths[OSFreeBSD])
	}
}
