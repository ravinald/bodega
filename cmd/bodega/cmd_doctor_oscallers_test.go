package main

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/host"
)

// fakeOS scripts the local tools osCallersHost runs: systemctl is-enabled
// motd-news.timer answers timer, systemctl is-active chrony.service answers
// chrony and chronyd.service answers chronyd, snapd.service answers snapd and
// snapd.socket answers socket, and snap refresh --time --abs-time answers refreshTime. calls logs every argv;
// ran logs only the ones not scripted, which is how a test sees what a step
// changed.
type fakeOS struct {
	timer, chrony, chronyd, snapd, socket, refreshTime string
	calls, ran                                         []string
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
	case "systemctl is-active chrony.service":
		if f.chrony == "" {
			return "inactive", errors.New("exit status 3")
		}
		return f.chrony, nil
	case "systemctl is-active chronyd.service":
		if f.chronyd == "" {
			return "inactive", errors.New("exit status 3")
		}
		return f.chronyd, nil
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
	case "snap refresh --time --abs-time":
		return f.refreshTime, nil
	}
	f.ran = append(f.ran, cmd)
	return "", nil
}

// oscRecord is where stubOSCallers puts the record under its fixture root, so
// a test seeds one through files.
const oscRecord = "/etc/bodega/doctor-os-callers.json"

// stubOSCallers points the package's osCallersHost at a fixture root holding
// files, and the record beneath it, for the length of the test.
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
	osCallers = &osCallersHost{goos: "linux", root: root, record: filepath.Join(root, oscRecord), run: f.run}
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

// ubuntuReleaseUpgrades is what Ubuntu 26.04 ships in
// /etc/update-manager/release-upgrades.
const ubuntuReleaseUpgrades = "# Default behavior for the release upgrader.\n\n" +
	"[DEFAULT]\n" +
	"# Default prompting and upgrade behavior, valid options:\n" +
	"#\n" +
	"#  never  - Never check for, or allow upgrading to, a new release.\n" +
	"#  normal - Check to see if a new release is available.\n" +
	"#  lts    - Check to see if a new LTS release is available.\n" +
	"Prompt=lts\n"

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
		want     host.Status // "" for no row
		detail   []string
		remedy   []string
	}{
		{"chrony over NTS", ubuntuChrony, fakeOS{chrony: "active"}, nil, "chrony-nts", host.StatusWarn,
			[]string{"1.ntp.ubuntu.com", "ntp-bootstrap.ubuntu.com", "TCP 4460", "keeps no time", "TLS", "Valid-Until"},
			[]string{"server <host> iburst", "allow TCP 4460"}},
		{"chrony through an included file", map[string]string{
			"/usr/sbin/chronyd":    "",
			"/etc/chrony.conf":     "include /etc/chrony.d/*.conf\n",
			"/etc/chrony.d/a.conf": "server time.cloudflare.com iburst nts\n"},
			fakeOS{chrony: "active"}, nil, "chrony-nts", host.StatusWarn, []string{"time.cloudflare.com"}, nil},
		{"chrony with an internal source the operator names", withFiles(ubuntuChrony, map[string]string{
			"/etc/chrony/conf.d/lan.conf": "server ntp.internal iburst\n"}),
			fakeOS{chrony: "active"}, []string{"NTP.internal"}, "chrony-nts", "", nil, nil},
		{"chrony from the bodega server over NTS", map[string]string{
			"/usr/sbin/chronyd":       "",
			"/etc/chrony/chrony.conf": "server bodega.internal iburst nts\n"},
			fakeOS{chrony: "active"}, []string{"bodega.internal"}, "chrony-nts", "", nil, nil},
		{"chrony without NTS", map[string]string{
			"/usr/sbin/chronyd":       "",
			"/etc/chrony/chrony.conf": "pool ntp.ubuntu.com iburst\n! server x nts\n"},
			fakeOS{chrony: "active"}, nil, "chrony-nts", "", nil, nil},
		{"chrony config left without chronyd", map[string]string{
			"/etc/chrony/chrony.conf": "server ntp-bootstrap.ubuntu.com nts\n"},
			fakeOS{chrony: "active"}, nil, "chrony-nts", "", nil, nil},
		{"chrony under its RHEL unit name", ubuntuChrony, fakeOS{chronyd: "active"}, nil, "chrony-nts", host.StatusWarn,
			[]string{"ntp-bootstrap.ubuntu.com"}, nil},
		{"chrony installed but not running", ubuntuChrony, fakeOS{chrony: "failed"}, nil, "chrony-nts", "", nil, nil},
		{"motd-news file and timer enabled", map[string]string{motdNewsDefaults: "# comment\nENABLED=1\n"},
			fakeOS{timer: "enabled"}, nil, "motd-news", host.StatusWarn,
			[]string{"ENABLED=1", "motd-news.timer is enabled", "needs both", "motd.ubuntu.com"},
			[]string{"ENABLED=0", "systemctl disable --now motd-news.timer"}},
		{"motd-news file enabled, timer disabled", map[string]string{motdNewsDefaults: "ENABLED=1\n"},
			fakeOS{timer: "disabled"}, nil, "motd-news", "", nil, nil},
		{"motd-news file enabled, no timer", map[string]string{motdNewsDefaults: "ENABLED=1\n"},
			fakeOS{}, nil, "motd-news", "", nil, nil},
		{"motd-news timer enabled, file disabled", map[string]string{motdNewsDefaults: "ENABLED=0\n"},
			fakeOS{timer: "enabled"}, nil, "motd-news", "", nil, nil},
		{"motd-news timer enabled, no file", nil, fakeOS{timer: "enabled"}, nil, "motd-news", "", nil, nil},
		{"motd-news off", map[string]string{motdNewsDefaults: "ENABLED=1\nENABLED=0\n"},
			fakeOS{timer: "disabled"}, nil, "motd-news", "", nil, nil},
		{"snapd active and unheld", snapd, fakeOS{snapd: "active", socket: "active", refreshTime: "timer: 00:00~24:00/4\nlast: n/a\nnext: n/a"},
			nil, "snapd-refresh", host.StatusWarn, []string{"api.snapcraft.io"}, []string{"snap refresh --hold", "proxy.store"}},
		{"snapd held forever", snapd, fakeOS{snapd: "active", refreshTime: "timer: 00:00~24:00/4\nhold: forever\nnext: n/a"},
			nil, "snapd-refresh", "", nil, nil},
		{"snapd held past 30 days", snapd, fakeOS{snapd: "active", refreshTime: "hold: " + time.Now().Add(31*24*time.Hour).UTC().Format(time.RFC3339)},
			nil, "snapd-refresh", "", nil, nil},
		{"snapd held under 30 days", snapd, fakeOS{snapd: "active", refreshTime: "hold: " + time.Now().Add(29*24*time.Hour).UTC().Format(time.RFC3339)},
			nil, "snapd-refresh", host.StatusWarn, []string{"api.snapcraft.io"}, nil},
		{"snapd hold lapsed", snapd, fakeOS{snapd: "active", refreshTime: "hold: 2026-10-20T13:05:00Z"},
			nil, "snapd-refresh", host.StatusWarn, []string{"api.snapcraft.io"}, nil},
		{"snapd in standby, no record", snapd, fakeOS{socket: "active"}, nil, "snapd-refresh", host.StatusWarn,
			[]string{"socket", "hold applied by hand cannot be seen without waking snapd", "--quiet-os-callers --apply records the hold in", oscRecord},
			[]string{"snap refresh --hold", "proxy.store"}},
		{"snapd in standby, hold recorded", withFiles(snapd, map[string]string{oscRecord: `{"steps": ["snap-refresh-hold"]}`}),
			fakeOS{socket: "active"}, nil, "snapd-refresh", "", nil, nil},
		{"snapd in standby, record without the hold", withFiles(snapd, map[string]string{oscRecord: `{"steps": ["motd-news"]}`}),
			fakeOS{socket: "active"}, nil, "snapd-refresh", host.StatusWarn, []string{"hold applied by hand"}, nil},
		{"snapd in standby, malformed record", withFiles(snapd, map[string]string{oscRecord: "{not json"}),
			fakeOS{socket: "active"}, nil, "snapd-refresh", host.StatusSkip,
			[]string{oscRecord, "is not the record --quiet-os-callers writes"}, []string{oscRecord, "move it aside"}},
		{"snapd in standby, record names an unknown step", withFiles(snapd, map[string]string{oscRecord: `{"steps": ["bogus"]}`}),
			fakeOS{socket: "active"}, nil, "snapd-refresh", host.StatusSkip, []string{oscRecord, `"bogus"`}, []string{"move it aside"}},
		{"snapd active and unheld, hold recorded", withFiles(snapd, map[string]string{oscRecord: `{"steps": ["snap-refresh-hold"]}`}),
			fakeOS{snapd: "active", refreshTime: "timer: 00:00~24:00/4"}, nil, "snapd-refresh", host.StatusWarn,
			[]string{"api.snapcraft.io", oscRecord + " says bodega applied a hold and snapd now reports none", "lifted by hand or lapsed"}, nil},
		{"snapd active and unheld, malformed record", withFiles(snapd, map[string]string{oscRecord: "{not json"}),
			fakeOS{snapd: "active", refreshTime: "timer: 00:00~24:00/4"}, nil, "snapd-refresh", host.StatusWarn, []string{"api.snapcraft.io"}, nil},
		{"snapd active and held, record malformed", withFiles(snapd, map[string]string{oscRecord: "{not json"}),
			fakeOS{snapd: "active", refreshTime: "hold: forever"}, nil, "snapd-refresh", "", nil, nil},
		{"snapd inactive", snapd, fakeOS{}, nil, "snapd-refresh", "", nil, nil},
		{"snapd not installed", nil, fakeOS{snapd: "active"}, nil, "snapd-refresh", "", nil, nil},
		{"release upgrades at lts", map[string]string{releaseUpgrades: ubuntuReleaseUpgrades}, fakeOS{}, nil,
			"release-upgrade-check", host.StatusWarn,
			[]string{releaseUpgrades, "Prompt=lts", "changelogs.ubuntu.com", "fetches no packages"},
			[]string{"Prompt=never", "--quiet-os-callers --apply", "--restore-os-callers"}},
		{"release upgrades with no Prompt line", map[string]string{releaseUpgrades: "[DEFAULT]\n"}, fakeOS{}, nil,
			"release-upgrade-check", host.StatusWarn, []string{"no Prompt line, which means Prompt=normal", "changelogs.ubuntu.com"}, nil},
		{"release upgrades at normal, spaced", map[string]string{releaseUpgrades: "[DEFAULT]\nprompt = normal\n"}, fakeOS{}, nil,
			"release-upgrade-check", host.StatusWarn, []string{"Prompt=normal"}, nil},
		{"release upgrades at never", map[string]string{releaseUpgrades: "[DEFAULT]\n# Prompt=lts\nPrompt=never\n"}, fakeOS{}, nil,
			"release-upgrade-check", host.StatusOK, []string{"Prompt=never"}, nil},
		{"release upgrades at never in another section only", map[string]string{releaseUpgrades: "[DEFAULT]\nPrompt=lts\n[other]\nPrompt=never\n"},
			fakeOS{}, nil, "release-upgrade-check", host.StatusWarn, []string{"Prompt=lts"}, nil},
		{"release upgrades absent", nil, fakeOS{}, nil, "release-upgrade-check", host.StatusNA, []string{"not installed"}, nil},
		{"release upgrades unreadable", map[string]string{releaseUpgrades + "/x": ""}, fakeOS{}, nil,
			"release-upgrade-check", host.StatusSkip, []string{"could not read", releaseUpgrades}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := tc.fake
			h := stubOSCallers(t, tc.files, &fake)
			fs := h.findings(tc.internal)
			f, ok := rowNamed(fs, tc.check)
			if ok != (tc.want != "") {
				t.Fatalf("%s row = %v (%+v), want %q", tc.check, ok, fs, tc.want)
			}
			for _, c := range fake.calls {
				if strings.HasPrefix(c, "systemctl is-") {
					continue
				}
				if c != "snap refresh --time --abs-time" || tc.fake.snapd != "active" {
					t.Errorf("a report ran %q; rows read files and systemctl, and ask snapd only while snapd.service runs", c)
				}
			}
			if !ok {
				return
			}
			if f.Status != tc.want {
				t.Errorf("status = %s, want %s", f.Status, tc.want)
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
	fake := &fakeOS{timer: "enabled", chrony: "active", snapd: "active"}
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

	fake := &fakeOS{timer: "enabled", chrony: "active", snapd: "active", refreshTime: "timer: 00:00~24:00/4\nlast: today\nnext: tomorrow"}
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

	standby := &fakeOS{socket: "active"}
	h := stubOSCallers(t, withFiles(files, map[string]string{motdNewsDefaults: "ENABLED=0\n", oscRecord: `{"steps": ["snap-refresh-hold"]}`}), standby)
	out, err = runDoctor(t, append(base, "--quiet-os-callers")...)
	if err != nil || !strings.Contains(out, "os-callers  nothing to quiet: motd-news is off, and snapd is in standby with its refresh hold recorded in "+h.record) {
		t.Errorf("a standby snapd with its hold recorded = %v, want nothing to quiet:\n%s", err, out)
	}
	if slices.ContainsFunc(standby.calls, func(c string) bool { return strings.HasPrefix(c, "snap ") }) {
		t.Errorf("planning against a standby snapd with its hold recorded ran %v; it would wake snapd", standby.calls)
	}

	unrecorded := &fakeOS{socket: "active", refreshTime: "timer: 00:00~24:00/4"}
	stubOSCallers(t, withFiles(files, map[string]string{motdNewsDefaults: "ENABLED=0\n"}), unrecorded)
	out, err = runDoctor(t, append(base, "--quiet-os-callers")...)
	if err != nil || !strings.Contains(out, "snapd-refresh  snap refresh --hold") || !slices.Contains(unrecorded.calls, "snap refresh --time --abs-time") {
		t.Errorf("a standby snapd with no record = %v, calls %v, want its hold read and planned:\n%s", err, unrecorded.calls, out)
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

// The rows and the steps that quiet them have to agree: once --apply has run
// every step, the next report carries neither row. The runner here plays the
// host, so each step changes what the next read answers.
func TestDoctorQuietOSCallersClearsItsRows(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv, _ := planServer(t, map[string]string{"apt": "deb x\n"})
	stubUbuntuPro(t, false, &fakePro{})
	fake := &fakeOS{timer: "enabled", snapd: "active", socket: "active", refreshTime: "timer: 00:00~24:00/4\nlast: n/a\nnext: n/a"}
	h := stubOSCallers(t, map[string]string{motdNewsDefaults: "ENABLED=1\n", "/usr/lib/snapd/snapd": ""}, fake)
	h.run = func(argv []string) (string, error) {
		out, err := fake.run(argv)
		switch strings.Join(argv, " ") {
		case strings.Join(osCallerSteps[oscStepMotdNews].do, " "):
			if werr := os.WriteFile(h.path(motdNewsDefaults), []byte("ENABLED=0\n"), 0o644); werr != nil {
				t.Fatal(werr)
			}
		case "systemctl disable --now motd-news.timer":
			fake.timer = "disabled"
		case "snap refresh --hold":
			fake.refreshTime = "timer: 00:00~24:00/4\nlast: n/a\nhold: forever\nnext: n/a"
		}
		return out, err
	}

	saved := doctorExit
	doctorExit = func(int) {}
	t.Cleanup(func() { doctorExit = saved })

	before, _ := runDoctor(t, "--url", srv.URL, "--allow-plaintext")
	for _, row := range []string{"motd-news", "snapd-refresh"} {
		if !strings.Contains(before, row+" ") {
			t.Fatalf("the unquieted host lacks the %s row:\n%s", row, before)
		}
	}

	out, err := runDoctor(t, "--configure", "apt", "--quiet-os-callers", "--apply", "--url", srv.URL, "--allow-plaintext")
	if err != nil {
		t.Fatalf("--apply = %v:\n%s", err, out)
	}
	if len(fake.ran) != 3 {
		t.Fatalf("--apply ran %v, want the three OS caller steps", fake.ran)
	}

	after, _ := runDoctor(t, "--url", srv.URL, "--allow-plaintext")
	if !strings.Contains(after, "CHECK") {
		t.Fatalf("the second run printed no report:\n%s", after)
	}
	for _, row := range []string{"motd-news", "snapd-refresh"} {
		if strings.Contains(after, row+" ") {
			t.Errorf("the %s row survived --quiet-os-callers --apply:\n%s", row, after)
		}
	}
}

// On a socket-activated snapd the hold --apply runs wakes snapd, which goes
// back to standby, so the next report cannot ask it and reads the record.
func TestDoctorQuietOSCallersClearsSnapdInStandby(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv, _ := planServer(t, map[string]string{"apt": "deb x\n"})
	stubUbuntuPro(t, false, &fakePro{})
	fake := &fakeOS{snapd: "", socket: "active", refreshTime: "timer: 00:00~24:00/4\nlast: n/a\nnext: n/a"}
	h := stubOSCallers(t, map[string]string{"/usr/lib/snapd/snapd": ""}, fake)

	saved := doctorExit
	doctorExit = func(int) {}
	t.Cleanup(func() { doctorExit = saved })

	before, _ := runDoctor(t, "--url", srv.URL, "--allow-plaintext")
	if !strings.Contains(before, "snapd-refresh ") {
		t.Fatalf("the unquieted standby host lacks the snapd-refresh row:\n%s", before)
	}

	out, err := runDoctor(t, "--configure", "apt", "--quiet-os-callers", "--apply", "--url", srv.URL, "--allow-plaintext")
	if err != nil {
		t.Fatalf("--apply = %v:\n%s", err, out)
	}
	if !slices.Equal(fake.ran, []string{"snap refresh --hold"}) {
		t.Fatalf("--apply ran %v, want the snapd hold alone", fake.ran)
	}
	b, err := os.ReadFile(h.record)
	if err != nil || !strings.Contains(string(b), `"snap-refresh-hold"`) {
		t.Fatalf("record after --apply = %s (%v), want snap-refresh-hold", b, err)
	}

	fake.calls = nil
	after, _ := runDoctor(t, "--url", srv.URL, "--allow-plaintext")
	if !strings.Contains(after, "CHECK") {
		t.Fatalf("the second run printed no report:\n%s", after)
	}
	if strings.Contains(after, "snapd-refresh ") {
		t.Errorf("the snapd-refresh row survived --quiet-os-callers --apply on a standby snapd:\n%s", after)
	}
	if slices.ContainsFunc(fake.calls, func(c string) bool { return strings.HasPrefix(c, "snap ") }) {
		t.Errorf("the report ran %v against a standby snapd", fake.calls)
	}
}

// --quiet-os-callers sets Prompt=never and records what it found, and
// --restore-os-callers puts the file back byte for byte, whatever form the
// Prompt line took or whether there was one at all.
func TestDoctorQuietOSCallersReleaseUpgradesRoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv, _ := planServer(t, map[string]string{"npm": "registry=x\n"})
	saved := doctorExit
	doctorExit = func(int) {}
	t.Cleanup(func() { doctorExit = saved })
	cases := []struct {
		name, body, step, found string
	}{
		{"ubuntu default", ubuntuReleaseUpgrades, "release-upgrade-prompt=lts", "found Prompt=lts"},
		{"spaced, lower-case key, CRLF", "[DEFAULT]\r\nprompt = normal  \r\n[x]\nPrompt=lts\n", "release-upgrade-prompt=normal", "found Prompt=normal"},
		{"colon, no final newline", "[DEFAULT]\nPrompt: lts", "release-upgrade-prompt=lts", "found Prompt=lts"},
		{"no Prompt line", "# c\n[DEFAULT]\nOther=1\n", "release-upgrade-prompt", "found no Prompt line"},
		{"no Prompt line, header unterminated", "[DEFAULT]", "release-upgrade-prompt", "found no Prompt line"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeOS{}
			h := stubOSCallers(t, map[string]string{releaseUpgrades: tc.body}, fake)
			args := []string{"--configure", "npm", "--quiet-os-callers", "--url", srv.URL, "--allow-plaintext"}

			out, err := runDoctor(t, args...)
			plan := "release-upgrade-check  set Prompt=never in " + releaseUpgrades + ", " + tc.found + "  (undo: bodega doctor --restore-os-callers)"
			if err != nil || !strings.Contains(out, plan) || !strings.Contains(out, "run the 1 OS caller step(s) above") {
				t.Fatalf("plan = %v, want %q:\n%s", err, plan, out)
			}
			if b, _ := os.ReadFile(h.path(releaseUpgrades)); string(b) != tc.body {
				t.Fatalf("the dry run wrote %q", b)
			}

			if out, err := runDoctor(t, append(args, "--apply")...); err != nil {
				t.Fatalf("--apply = %v:\n%s", err, out)
			}
			p, err := h.readPrompt()
			if err != nil || !p.never() {
				t.Fatalf("after --apply Prompt = %q (%v), want never", p.value(), err)
			}
			rec, err := os.ReadFile(h.record)
			if err != nil || !strings.Contains(string(rec), `"`+tc.step+`"`) {
				t.Fatalf("record = %s (%v), want %q", rec, err, tc.step)
			}
			report, _ := runDoctor(t, "--url", srv.URL, "--allow-plaintext")
			if f, _ := h.releaseUpgradeCheck(); f.Status != host.StatusOK || !strings.Contains(report, "release-upgrade-check") {
				t.Errorf("after --apply the row is %s, want OK:\n%s", f.Status, report)
			}
			if out, _ := runDoctor(t, args...); !strings.Contains(out, "nothing to quiet") || !strings.Contains(out, "release-upgrade check is off") {
				t.Errorf("a second plan after --apply is not empty:\n%s", out)
			}

			if out, err := runDoctor(t, "--restore-os-callers"); err != nil {
				t.Fatalf("--restore-os-callers = %v:\n%s", err, out)
			}
			if b, _ := os.ReadFile(h.path(releaseUpgrades)); string(b) != tc.body {
				t.Errorf("restored file = %q, want %q", b, tc.body)
			}
			if _, err := os.Stat(h.record); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("record survived a complete restore: %v", err)
			}
			if len(fake.ran) != 0 {
				t.Errorf("the edit ran tools: %v", fake.ran)
			}
		})
	}
}

func TestReleaseUpgradeStepNames(t *testing.T) {
	h := &osCallersHost{root: t.TempDir()}
	for name, ok := range map[string]bool{
		"release-upgrade-prompt": true, "release-upgrade-prompt=lts": true, "release-upgrade-prompt=": true,
		"release-upgrade-promptx": false, "motd": false,
	} {
		if _, got := h.releaseUpgradeStep(name); got != ok {
			t.Errorf("releaseUpgradeStep(%q) = %v, want %v", name, got, ok)
		}
	}
}
