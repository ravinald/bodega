package clientconf

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
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
