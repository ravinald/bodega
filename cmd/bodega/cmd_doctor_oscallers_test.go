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

// fakeOS scripts the local tools osCallersHost runs: systemctl is-enabled
// motd-news.timer answers timer, systemctl is-active snapd.service answers
// snapd and snapd.socket answers socket, and snap refresh --time answers
// refreshTime. calls logs every argv;
// ran logs only the ones not scripted, which is how a test sees what a step
// changed.
type fakeOS struct {
	timer, snapd, socket, refreshTime string
	calls, ran                        []string
}

func (f *fakeOS) run(argv []string) (string, error) {
	cmd := strings.Join(argv, " ")
	f.calls = append(f.calls, cmd)
	switch cmd {
	case "systemctl is-enabled motd-news.timer":
		if f.timer == "" {
			return "Failed to get unit file state for motd-news.timer: No such file or directory", errors.New("exit status 1")
		}
		return f.timer, nil
	case "systemctl is-active snapd.service":
		if f.snapd == "" {
			return "inactive", errors.New("exit status 3")
		}
		return f.snapd, nil
	case "systemctl is-active snapd.socket":
		if f.socket == "" {
			return "inactive", errors.New("exit status 3")
		}
		return f.socket, nil
	case "snap refresh --time":
		return f.refreshTime, nil
	}
	f.ran = append(f.ran, cmd)
	return "", nil
}

// stubOSCallers points the package's osCallersHost at a fixture root holding
// files, and a scratch record, for the length of the test.
func stubOSCallers(t *testing.T, files map[string]string, f *fakeOS) *osCallersHost {
	t.Helper()
	root := t.TempDir()
	for p, body := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	saved := osCallers
	osCallers = &osCallersHost{goos: "linux", root: root, record: filepath.Join(t.TempDir(), "etc", "doctor-os-callers.json"), run: f.run}
	t.Cleanup(func() { osCallers = saved })
	return osCallers
}

// ubuntuChrony is what Ubuntu 26.04 ships: chrony.conf pulls its pools in
// through sourcedir, and those use NTS.
var ubuntuChrony = map[string]string{
	"/usr/sbin/chronyd": "",
	"/etc/chrony/chrony.conf": "confdir /etc/chrony/conf.d\n" +
		"sourcedir /run/chrony-dhcp\n" +
		"sourcedir /etc/chrony/sources.d\n" +
		"ntsdumpdir /var/lib/chrony\n",
	"/etc/chrony/sources.d/ubuntu-ntp-pools.sources": "# Use NTS by default\n" +
		"pool 1.ntp.ubuntu.com iburst maxsources 1 nts prefer\n" +
		"pool 2.ntp.ubuntu.com iburst maxsources 1 nts prefer\n" +
		"server ntp-bootstrap.ubuntu.com iburst nts\n",
}

func withFiles(base map[string]string, extra map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

func rowNamed(fs []host.Finding, check string) (host.Finding, bool) {
	for _, f := range fs {
		if f.Check == check {
			return f, true
		}
	}
	return host.Finding{}, false
}

func TestOSCallerRows(t *testing.T) {
	snapd := map[string]string{"/usr/lib/snapd/snapd": ""}
	cases := []struct {
		name     string
		files    map[string]string
		fake     fakeOS
		internal []string
		check    string
		want     bool
		detail   []string
		remedy   []string
	}{
		{"chrony over NTS", ubuntuChrony, fakeOS{}, nil, "chrony-nts", true,
			[]string{"1.ntp.ubuntu.com", "ntp-bootstrap.ubuntu.com", "TCP 4460", "keeps no time", "TLS", "Valid-Until"},
			[]string{"server <host> iburst", "allow TCP 4460"}},
		{"chrony through an included file", map[string]string{
			"/usr/sbin/chronyd":    "",
			"/etc/chrony.conf":     "include /etc/chrony.d/*.conf\n",
			"/etc/chrony.d/a.conf": "server time.cloudflare.com iburst nts\n"},
			fakeOS{}, nil, "chrony-nts", true, []string{"time.cloudflare.com"}, nil},
		{"chrony with an internal source the operator names", withFiles(ubuntuChrony, map[string]string{
			"/etc/chrony/conf.d/lan.conf": "server ntp.internal iburst\n"}),
			fakeOS{}, []string{"NTP.internal"}, "chrony-nts", false, nil, nil},
		{"chrony from the bodega server over NTS", map[string]string{
			"/usr/sbin/chronyd":       "",
			"/etc/chrony/chrony.conf": "server bodega.internal iburst nts\n"},
			fakeOS{}, []string{"bodega.internal"}, "chrony-nts", false, nil, nil},
		{"chrony without NTS", map[string]string{
			"/usr/sbin/chronyd":       "",
			"/etc/chrony/chrony.conf": "pool ntp.ubuntu.com iburst\n! server x nts\n"},
			fakeOS{}, nil, "chrony-nts", false, nil, nil},
		{"chrony config left without chronyd", map[string]string{
			"/etc/chrony/chrony.conf": "server ntp-bootstrap.ubuntu.com nts\n"},
			fakeOS{}, nil, "chrony-nts", false, nil, nil},
		{"motd-news file enabled", map[string]string{motdNewsDefaults: "# comment\nENABLED=1\n"},
			fakeOS{}, nil, "motd-news", true,
			[]string{"ENABLED=1", "motd.ubuntu.com"},
			[]string{"ENABLED=0", "systemctl disable --now motd-news.timer"}},
		{"motd-news timer enabled", map[string]string{motdNewsDefaults: "ENABLED=0\n"},
			fakeOS{timer: "enabled"}, nil, "motd-news", true, []string{"motd-news.timer is enabled"}, nil},
		{"motd-news off", map[string]string{motdNewsDefaults: "ENABLED=1\nENABLED=0\n"},
			fakeOS{timer: "disabled"}, nil, "motd-news", false, nil, nil},
		{"snapd active", snapd, fakeOS{snapd: "active"}, nil, "snapd-refresh", true,
			[]string{"api.snapcraft.io"}, []string{"snap refresh --hold", "proxy.store"}},
		{"snapd in standby behind its socket", snapd, fakeOS{socket: "active"}, nil, "snapd-refresh", true,
			[]string{"socket"}, nil},
		{"snapd inactive", snapd, fakeOS{}, nil, "snapd-refresh", false, nil, nil},
		{"snapd not installed", nil, fakeOS{snapd: "active"}, nil, "snapd-refresh", false, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := tc.fake
			h := stubOSCallers(t, tc.files, &fake)
			fs := h.findings(tc.internal)
			f, ok := rowNamed(fs, tc.check)
			if ok != tc.want {
				t.Fatalf("%s row = %v (%+v), want %v", tc.check, ok, fs, tc.want)
			}
			for _, c := range fake.calls {
				if !strings.HasPrefix(c, "systemctl is-") {
					t.Errorf("a report ran %q; rows read files and systemctl alone", c)
				}
			}
			if !ok {
				return
			}
			if f.Status != host.StatusWarn {
				t.Errorf("status = %s, want WARN", f.Status)
			}
			for _, want := range tc.detail {
				if !strings.Contains(f.Detail, want) {
					t.Errorf("detail lacks %q: %s", want, f.Detail)
				}
			}
			for _, want := range tc.remedy {
				if !strings.Contains(f.Remediation, want) {
					t.Errorf("remediation lacks %q: %s", want, f.Remediation)
				}
			}
		})
	}
}

func TestOSCallerRowsAbsentOffLinux(t *testing.T) {
	fake := &fakeOS{timer: "enabled", snapd: "active"}
	h := stubOSCallers(t, withFiles(ubuntuChrony, map[string]string{motdNewsDefaults: "ENABLED=1\n"}), fake)
	h.goos = "freebsd"
	if fs := h.findings(nil); len(fs) != 0 || len(fake.calls) != 0 {
		t.Errorf("findings = %+v, calls %v; want none off Linux", fs, fake.calls)
	}
}

func TestDoctorConfigureQuietOSCallersPlan(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv, _ := planServer(t, map[string]string{"npm": "registry=x\n"})
	base := []string{"--configure", "npm", "--url", srv.URL, "--allow-plaintext"}
	files := withFiles(ubuntuChrony, map[string]string{motdNewsDefaults: "ENABLED=1\n", "/usr/lib/snapd/snapd": ""})

	fake := &fakeOS{timer: "enabled", snapd: "active", refreshTime: "timer: 00:00~24:00/4\nlast: today\nnext: tomorrow"}
	stubOSCallers(t, files, fake)
	out, err := runDoctor(t, base...)
	if err != nil || strings.Contains(out, "motd-news") || len(fake.calls) != 0 {
		t.Fatalf("without --quiet-os-callers = %v, calls %v, want no OS caller step:\n%s", err, fake.calls, out)
	}

	out, err = runDoctor(t, append(base, "--quiet-os-callers")...)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"motd-news  sed -i 's/^[[:space:]]*ENABLED=.*/ENABLED=0/' /etc/default/motd-news  (undo: sed -i 's/^[[:space:]]*ENABLED=.*/ENABLED=1/' /etc/default/motd-news)",
		"motd-news  systemctl disable --now motd-news.timer  (undo: systemctl enable --now motd-news.timer)",
		"snapd-refresh  snap refresh --hold  (undo: snap refresh --unhold)",
		"run the 3 OS caller step(s) above",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("plan lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "chrony") {
		t.Errorf("the plan touches chrony:\n%s", out)
	}
	if len(fake.ran) != 0 {
		t.Errorf("the dry run ran %v", fake.ran)
	}

	stubOSCallers(t, withFiles(files, map[string]string{motdNewsDefaults: "ENABLED=0\n"}),
		&fakeOS{snapd: "active", refreshTime: "timer: 00:00~24:00/4\nhold: forever"})
	out, err = runDoctor(t, append(base, "--quiet-os-callers")...)
	if err != nil || !strings.Contains(out, "os-callers  nothing to quiet: motd-news is off, and snapd is already held") {
		t.Errorf("a quiet host = %v, want nothing to quiet:\n%s", err, out)
	}

	if _, err := runDoctor(t, "--quiet-os-callers"); err == nil {
		t.Error("--quiet-os-callers without --configure was accepted")
	}
	if _, err := runDoctor(t, "--restore-os-callers", "--configure", "npm"); err == nil {
		t.Error("--restore-os-callers with --configure was accepted")
	}
}

// The restore undoes what the quiet run changed and nothing it found already
// done: a motd-news.timer somebody disabled by hand stays disabled.
func TestDoctorRestoreOSCallersUndoesOnlyWhatItRan(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv, _ := planServer(t, map[string]string{"npm": "registry=x\n"})
	fake := &fakeOS{timer: "disabled", snapd: "active", refreshTime: "timer: 00:00~24:00/4"}
	h := stubOSCallers(t, map[string]string{motdNewsDefaults: "ENABLED=1\n", "/usr/lib/snapd/snapd": ""}, fake)

	out, err := runDoctor(t, "--configure", "npm", "--quiet-os-callers", "--apply", "--url", srv.URL, "--allow-plaintext")
	if err != nil {
		t.Fatalf("--apply = %v:\n%s", err, out)
	}
	want := []string{"sed -i s/^[[:space:]]*ENABLED=.*/ENABLED=0/ /etc/default/motd-news", "snap refresh --hold"}
	if !slices.Equal(fake.ran, want) {
		t.Fatalf("--apply ran %v, want %v", fake.ran, want)
	}
	if !strings.Contains(out, "recorded   "+h.record+" (undo: bodega doctor --restore-os-callers)") {
		t.Errorf("--apply did not name the record and its undo:\n%s", out)
	}
	b, err := os.ReadFile(h.record)
	if err != nil {
		t.Fatalf("no record after --apply: %v", err)
	}
	if !strings.Contains(string(b), `"motd-news"`) || !strings.Contains(string(b), `"snap-refresh-hold"`) || strings.Contains(string(b), "timer") {
		t.Errorf("record = %s, want motd-news and snap-refresh-hold only", b)
	}

	fake.ran = nil
	if out, err := runDoctor(t, "--restore-os-callers"); err != nil {
		t.Fatalf("--restore-os-callers = %v:\n%s", err, out)
	}
	want = []string{"sed -i s/^[[:space:]]*ENABLED=.*/ENABLED=1/ /etc/default/motd-news", "snap refresh --unhold"}
	if !slices.Equal(fake.ran, want) {
		t.Errorf("restore ran %v, want %v", fake.ran, want)
	}
	if _, err := os.Stat(h.record); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("record survived a complete restore: %v", err)
	}

	fake.ran = nil
	out, err = runDoctor(t, "--restore-os-callers")
	if err != nil || len(fake.ran) != 0 || !strings.Contains(out, "Nothing to restore") {
		t.Errorf("second restore = %v, ran %v:\n%s", err, fake.ran, out)
	}
}
