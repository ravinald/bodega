package main

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/host"
)

// fakePro scripts the tools proHost runs: pro status answers attached,
// pro config show answers aptNews, and systemctl is-enabled answers unit.
// Every other argv succeeds and is logged, which is how a test sees what a
// step changed.
type fakePro struct {
	attached string
	aptNews  string
	unit     string
	ran      []string
}

func (f *fakePro) run(argv []string) (string, error) {
	cmd := strings.Join(argv, " ")
	switch cmd {
	case "pro status --format json":
		return `{"_doc":"x","attached":` + f.attached + `,"services":[]}`, nil
	case "pro config show apt_news":
		return "apt_news " + f.aptNews, nil
	case "systemctl is-enabled esm-cache.service":
		if strings.HasPrefix(f.unit, "masked") {
			return f.unit, errors.New("exit status 1")
		}
		return f.unit, nil
	}
	f.ran = append(f.ran, cmd)
	return "", nil
}

// stubUbuntuPro points the package's proHost at a fixture root and a scratch
// record for the length of the test.
func stubUbuntuPro(t *testing.T, hook bool, f *fakePro) *proHost {
	t.Helper()
	root := t.TempDir()
	if hook {
		path := filepath.Join(root, esmHookConf)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("APT::Update::Pre-Invoke {};\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	saved := ubuntuPro
	ubuntuPro = &proHost{root: root, record: filepath.Join(t.TempDir(), "etc", "doctor-ubuntu-pro.json"), run: f.run}
	t.Cleanup(func() { ubuntuPro = saved })
	return ubuntuPro
}

func TestUbuntuProHookRow(t *testing.T) {
	cases := []struct {
		name     string
		hook     bool
		attached string
		wantRow  bool
	}{
		{"unattached with the hook", true, "false", true},
		{"attached with the hook", true, "true", false},
		{"no hook", false, "false", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := stubUbuntuPro(t, tc.hook, &fakePro{attached: tc.attached})
			f, ok := h.finding()
			if ok != tc.wantRow {
				t.Fatalf("row = %v (%+v), want %v", ok, f, tc.wantRow)
			}
			if !ok {
				return
			}
			if f.Status != host.StatusWarn {
				t.Errorf("status = %s, want WARN", f.Status)
			}
			for _, want := range []string{esmHookConf, "esm.ubuntu.com"} {
				if !strings.Contains(f.Detail, want) {
					t.Errorf("detail lacks %q: %s", want, f.Detail)
				}
			}
			for _, want := range []string{"pro config set apt_news=false", "systemctl mask esm-cache.service"} {
				if !strings.Contains(f.Remediation, want) {
					t.Errorf("remediation lacks %q: %s", want, f.Remediation)
				}
			}
		})
	}
}

// A pro that will not answer leaves the question open, and the row says the
// check did not run rather than guessing either way.
func TestUbuntuProHookRowSkipsWhenProFails(t *testing.T) {
	h := stubUbuntuPro(t, true, &fakePro{})
	h.run = func([]string) (string, error) { return "boom", errors.New("exit status 1") }
	f, ok := h.finding()
	if !ok || f.Status != host.StatusSkip {
		t.Fatalf("finding = %v %+v, want a SKIPPED row", ok, f)
	}
}

func TestDoctorConfigureQuietUbuntuProPlan(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv, _ := planServer(t, map[string]string{"apt": "Types: deb\n"})
	base := []string{"--configure", "apt", "--url", srv.URL, "--allow-plaintext"}

	fake := &fakePro{attached: "false", aptNews: "True", unit: "static"}
	stubUbuntuPro(t, true, fake)
	out, err := runDoctor(t, base...)
	if err != nil || strings.Contains(out, "apt_news") || strings.Contains(out, "esm-cache") {
		t.Fatalf("without --quiet-ubuntu-pro = %v, want no Ubuntu Pro step:\n%s", err, out)
	}

	out, err = runDoctor(t, append(base, "--quiet-ubuntu-pro")...)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"pro config set apt_news=false  (undo: pro config set apt_news=true)",
		"systemctl mask esm-cache.service  (undo: systemctl unmask esm-cache.service)",
		"Dry run: nothing was written",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("plan lacks %q:\n%s", want, out)
		}
	}
	if len(fake.ran) != 0 {
		t.Errorf("the dry run ran %v", fake.ran)
	}

	stubUbuntuPro(t, true, &fakePro{attached: "true"})
	out, err = runDoctor(t, append(base, "--quiet-ubuntu-pro")...)
	if err != nil || !strings.Contains(out, "nothing to quiet") {
		t.Errorf("attached host = %v, want nothing to quiet:\n%s", err, out)
	}

	if _, err := runDoctor(t, "--configure", "npm", "--quiet-ubuntu-pro", "--url", srv.URL); err == nil {
		t.Error("--quiet-ubuntu-pro without apt was accepted")
	}
	if _, err := runDoctor(t, "--quiet-ubuntu-pro"); err == nil {
		t.Error("--quiet-ubuntu-pro without --configure was accepted")
	}
}

// The restore undoes what the quiet run changed and nothing it found already
// done: an operator who masked esm-cache.service by hand keeps it masked.
func TestDoctorRestoreUbuntuProUndoesOnlyWhatItRan(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv, _ := planServer(t, map[string]string{"apt": "Types: deb\n"})
	fake := &fakePro{attached: "false", aptNews: "True", unit: "masked"}
	h := stubUbuntuPro(t, true, fake)

	out, err := runDoctor(t, "--configure", "apt", "--quiet-ubuntu-pro", "--apply", "--url", srv.URL, "--allow-plaintext")
	if err != nil {
		t.Fatalf("--apply = %v:\n%s", err, out)
	}
	if want := []string{"pro config set apt_news=false"}; !slices.Equal(fake.ran, want) {
		t.Fatalf("--apply ran %v, want %v", fake.ran, want)
	}
	if _, err := os.Stat(h.record); err != nil {
		t.Fatalf("no record after --apply: %v", err)
	}

	fake.ran = nil
	if out, err := runDoctor(t, "--restore-ubuntu-pro"); err != nil {
		t.Fatalf("--restore-ubuntu-pro = %v:\n%s", err, out)
	}
	if want := []string{"pro config set apt_news=true"}; !slices.Equal(fake.ran, want) {
		t.Errorf("restore ran %v, want %v", fake.ran, want)
	}
	if _, err := os.Stat(h.record); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("record survived a complete restore: %v", err)
	}

	fake.ran = nil
	out, err = runDoctor(t, "--restore-ubuntu-pro")
	if err != nil || len(fake.ran) != 0 || !strings.Contains(out, "Nothing to restore") {
		t.Errorf("second restore = %v, ran %v:\n%s", err, fake.ran, out)
	}
}
