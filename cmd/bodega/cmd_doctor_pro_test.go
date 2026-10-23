package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/host"
)

// fakePro scripts the tools proHost runs: pro api and pro status answer
// attached, pro config show answers aptNews, and systemctl is-enabled answers
// unit. api set to "unknown" makes pro api fail as an ubuntu-pro-client that
// predates it, and "failure" makes it return a failed result; statusErr makes
// pro status fail with it, and lookErr makes the lookup of pro fail with it.
// calls logs every argv; ran logs only the ones not
// scripted above, which is how a test sees what a step changed.
type fakePro struct {
	attached  string
	api       string
	statusErr error
	lookErr   error
	aptNews   string
	unit      string
	calls     []string
	ran       []string
}

func (f *fakePro) lookPath(file string) (string, error) {
	if f.lookErr != nil {
		return "", &exec.Error{Name: file, Err: f.lookErr}
	}
	return "/usr/bin/" + file, nil
}

func (f *fakePro) run(argv []string) (string, error) {
	cmd := strings.Join(argv, " ")
	f.calls = append(f.calls, cmd)
	switch cmd {
	case "pro api u.pro.status.is_attached.v1":
		switch f.api {
		case "unknown":
			return "usage: pro <command> [flags]\nargument <command>: invalid choice: 'api'", errors.New("exit status 2")
		case "failure":
			return `{"_schema_version":"v1","data":{"meta":{}},"errors":[{"title":"x"}],"result":"failure"}`, errors.New("exit status 1")
		}
		return `{"_schema_version":"v1","data":{"attributes":{"is_attached":` + f.attached + `},"type":"IsAttached"},"result":"success"}`, nil
	case "pro status --format json":
		if f.statusErr != nil {
			return "", f.statusErr
		}
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
	ubuntuPro = &proHost{root: root, record: filepath.Join(t.TempDir(), "etc", "doctor-ubuntu-pro.json"), run: f.run, lookPath: f.lookPath}
	t.Cleanup(func() { ubuntuPro = saved })
	return ubuntuPro
}

func TestUbuntuProHookRow(t *testing.T) {
	cases := []struct {
		name     string
		hook     bool
		attached string
		api      string
		wantRow  bool
	}{
		{"unattached with the hook", true, "false", "", true},
		{"attached with the hook", true, "true", "", false},
		{"no hook", false, "false", "", false},
		{"pro api unknown, pro status unattached", true, "false", "unknown", true},
		{"pro api failure, pro status unattached", true, "false", "failure", true},
		{"pro api unknown, pro status attached", true, "true", "unknown", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakePro{attached: tc.attached, api: tc.api}
			h := stubUbuntuPro(t, tc.hook, fake)
			f, ok := h.finding()
			if ok != tc.wantRow {
				t.Fatalf("row = %v (%+v), want %v", ok, f, tc.wantRow)
			}
			askedStatus := slices.Contains(fake.calls, "pro status --format json")
			if wantStatus := tc.hook && tc.api != ""; askedStatus != wantStatus {
				t.Errorf("pro status asked = %v, want %v; calls %v", askedStatus, wantStatus, fake.calls)
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
// check did not run rather than guessing either way. A pro status cut off at
// the bound is the egress-locked host, so the row names the steps to run by
// hand rather than leaving the operator to guess why.
func TestUbuntuProHookRowSkipsWhenProFails(t *testing.T) {
	cases := []struct {
		name      string
		statusErr error
		want      []string
		wantNot   []string
	}{
		{"pro status fails", errors.New("exit status 1"),
			[]string{"`pro api u.pro.status.is_attached.v1` failed", "`pro status --format json` failed"},
			[]string{"contract server"}},
		{"pro status times out", fmt.Errorf("no answer within 30s, %w: signal: killed", context.DeadlineExceeded),
			[]string{"`pro api u.pro.status.is_attached.v1` failed", "`pro status --format json` failed",
				"Canonical's contract server", "pro config set apt_news=false", "systemctl mask esm-cache.service"},
			nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := stubUbuntuPro(t, true, &fakePro{api: "unknown", statusErr: tc.statusErr})
			f, ok := h.finding()
			if !ok || f.Status != host.StatusSkip {
				t.Fatalf("finding = %v %+v, want a SKIPPED row", ok, f)
			}
			for _, want := range tc.want {
				if !strings.Contains(f.Detail, want) {
					t.Errorf("detail lacks %q: %s", want, f.Detail)
				}
			}
			for _, not := range tc.wantNot {
				if strings.Contains(f.Detail, not) {
					t.Errorf("detail carries %q: %s", not, f.Detail)
				}
			}
		})
	}
}

// The hook is a dpkg conffile, so a removed but unpurged ubuntu-pro-client
// leaves it behind with no pro to run it. That host has nothing to report and
// nothing to quiet, and doctor asks no pro anything.
func TestUbuntuProHookLeftoverWithoutPro(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	fake := &fakePro{lookErr: exec.ErrNotFound}
	h := stubUbuntuPro(t, true, fake)
	if f, ok := h.finding(); ok {
		t.Fatalf("finding = %+v, want no row", f)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("finding ran %v with pro gone", fake.calls)
	}

	srv, _ := planServer(t, map[string]string{"apt": "Types: deb\n"})
	out, err := runDoctor(t, "--configure", "apt", "--quiet-ubuntu-pro", "--apply", "--url", srv.URL, "--allow-plaintext")
	if err != nil {
		t.Fatalf("--apply = %v:\n%s", err, out)
	}
	want := "nothing to quiet: 20apt-esm-hook.conf is left from a removed ubuntu-pro-client; nothing runs it"
	if !strings.Contains(out, want) {
		t.Errorf("plan lacks %q:\n%s", want, out)
	}
	if len(fake.calls) != 0 {
		t.Errorf("--quiet-ubuntu-pro ran %v with pro gone", fake.calls)
	}
	if _, err := os.Stat(h.record); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("--apply wrote %s with nothing to quiet: %v", h.record, err)
	}
}

// A lookup that fails for any reason but absence leaves the question open.
func TestUbuntuProHookRowSkipsWhenLookupFails(t *testing.T) {
	fake := &fakePro{lookErr: os.ErrPermission}
	h := stubUbuntuPro(t, true, fake)
	f, ok := h.finding()
	if !ok || f.Status != host.StatusSkip || !strings.Contains(f.Detail, "looking up `pro` in $PATH failed") {
		t.Fatalf("finding = %v %+v, want a SKIPPED row naming the lookup", ok, f)
	}
	if len(fake.calls) != 0 {
		t.Errorf("finding ran %v after the lookup failed", fake.calls)
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
	if slices.Contains(fake.calls, "pro status --format json") {
		t.Errorf("pro api answered and pro status was still asked: %v", fake.calls)
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
