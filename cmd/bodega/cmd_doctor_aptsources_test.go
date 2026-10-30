package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/clientconf"
	"github.com/ravinald/bodega/internal/host"
	"github.com/ravinald/bodega/internal/manifest"
)

const resoluteUbuntuSources = `## See the sources.list(5) manual page for further settings.

Types: deb
URIs: http://archive.ubuntu.com/ubuntu/
Suites: resolute resolute-updates resolute-backports
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

## Ubuntu security updates.
Types: deb
URIs: http://security.ubuntu.com/ubuntu/
Suites: resolute-security
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
`

const dockerSources = "Types: deb\nURIs: https://download.docker.com/linux/ubuntu\nSuites: resolute\nComponents: stable\n"

// aptPlanServer answers /client/plan with bodega.sources, rooted under the
// caller's home, naming the server's own host.
func aptPlanServer(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	body := func() string {
		return "Types: deb\nURIs: " + srv.URL + "/apt/ubuntu\nSuites: resolute\nComponents: main\n"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /client/plan", func(w http.ResponseWriter, r *http.Request) {
		sum := sha256.Sum256([]byte(body()))
		_ = json.NewEncoder(w).Encode(clientconf.Plan{Records: []clientconf.PlanRecord{{
			Identity: "ubuntu-host", Match: "cidr:192.0.2.1/32", System: manifest.TypeApt, Action: clientconf.PlanInstall,
			Path: "~" + clientconf.AptSourcesPath, URL: srv.URL + "/client/apt", SHA256: hex.EncodeToString(sum[:]),
		}}})
	})
	mux.HandleFunc("GET /client/apt", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, body()) })
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// stubAptHost points aptSources at home, where the plan's bodega.sources
// lands, and doctorRun at a recorder that fails with fail when it is set.
func stubAptHost(t *testing.T, home string, ran *[]string, fail *error) {
	t.Helper()
	savedHost, savedRun := aptSources, doctorRun
	aptSources = &aptSourcesHost{goos: "linux", root: home, record: filepath.Join(home, "/etc/bodega/doctor-apt-sources.json")}
	doctorRun = func(name string, args ...string) error {
		*ran = append(*ran, shellJoin(append([]string{name}, args...)))
		return *fail
	}
	t.Cleanup(func() { aptSources, doctorRun = savedHost, savedRun })
}

func TestDoctorConfigureAptDisablesDistroSourcesAndRestores(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	files := map[string]string{
		"/etc/apt/sources.list.d/ubuntu.sources": resoluteUbuntuSources,
		"/etc/apt/sources.list.d/docker.sources": dockerSources,
		"/etc/apt/sources.list":                  "# Ubuntu sources have moved to /etc/apt/sources.list.d/ubuntu.sources\n",
	}
	for p, body := range files {
		full := filepath.Join(home, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var ran []string
	var fail error
	stubAptHost(t, home, &ran, &fail)
	srv := aptPlanServer(t)
	args := []string{"--configure", "apt", "--url", srv.URL, "--allow-plaintext"}
	ubuntu := filepath.Join(home, "/etc/apt/sources.list.d/ubuntu.sources")
	read := func(p string) string {
		b, _ := os.ReadFile(filepath.Join(home, p))
		return string(b)
	}

	out, err := runDoctor(t, args...)
	if err != nil {
		t.Fatalf("dry run = %v:\n%s", err, out)
	}
	for _, want := range []string{
		"disable    apt        /etc/apt/sources.list.d/ubuntu.sources:3  http://archive.ubuntu.com/ubuntu/ names archive.ubuntu.com; adds Enabled: no",
		"disable    apt        /etc/apt/sources.list.d/ubuntu.sources:10  http://security.ubuntu.com/ubuntu/ names security.ubuntu.com",
		"keep       apt        /etc/apt/sources.list.d/docker.sources:1  https://download.docker.com/linux/ubuntu names neither a public archive nor bodega; left in place",
		"1 apt source edit(s)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dry run lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "bodega.sources:") || len(ran) != 0 || read("/etc/apt/sources.list.d/ubuntu.sources") != resoluteUbuntuSources {
		t.Fatalf("the dry run touched something: ran %v\n%s", ran, out)
	}

	fail = errors.New("exit status 100")
	out, err = runDoctor(t, append(args, "--apply")...)
	if err == nil || !strings.Contains(err.Error(), "nothing in the distro's sources was disabled") {
		t.Fatalf("--apply with a failing update = %v:\n%s", err, out)
	}
	if len(ran) != 1 || !strings.HasPrefix(ran[0], "apt-get update -o Dir::Etc::SourceList="+filepath.Join(home, clientconf.AptSourcesPath)+" -o Dir::Etc::SourceParts=-") {
		t.Errorf("gate ran %v", ran)
	}
	if got, _ := os.ReadFile(ubuntu); string(got) != resoluteUbuntuSources {
		t.Errorf("a failed update still disabled ubuntu.sources:\n%s", got)
	}
	if _, err := os.Stat(aptSources.record); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a failed update left a record: %v", err)
	}
	if !strings.Contains(read(clientconf.AptSourcesPath), srv.URL) {
		t.Error("bodega.sources was not written before the gate")
	}

	fail, ran = nil, nil
	out, err = runDoctor(t, append(args, "--apply")...)
	if err != nil {
		t.Fatalf("--apply = %v:\n%s", err, out)
	}
	if !strings.Contains(out, "recorded   "+aptSources.record+" (undo: bodega doctor --restore-apt-sources)") {
		t.Errorf("--apply did not name its record:\n%s", out)
	}
	if got := read("/etc/apt/sources.list.d/ubuntu.sources"); strings.Count(got, "Enabled: no\n") != 2 {
		t.Errorf("ubuntu.sources after --apply:\n%s", got)
	}
	if read("/etc/apt/sources.list.d/docker.sources") != dockerSources {
		t.Error("--apply edited the third-party source")
	}
	var rec proRecord
	if b, err := os.ReadFile(aptSources.record); err != nil || json.Unmarshal(b, &rec) != nil || len(rec.Steps) != 1 {
		t.Errorf("record = %+v (%v)", rec, err)
	} else if e, err := host.ParseAptEdit(rec.Steps[0]); err != nil || e.String() != "deb822 /etc/apt/sources.list.d/ubuntu.sources 3,10" {
		t.Errorf("recorded edit = %v (%v)", e, err)
	}

	ran = nil
	out, err = runDoctor(t, append(args, "--apply")...)
	if err != nil || !strings.Contains(out, "Nothing to change") || len(ran) != 0 || strings.Contains(out, "disable ") {
		t.Errorf("second --apply = %v, ran %v:\n%s", err, ran, out)
	}

	if _, err := runDoctor(t, "--restore-apt-sources", "--configure", "apt"); err == nil {
		t.Error("--restore-apt-sources with --configure was accepted")
	}
	out, err = runDoctor(t, "--restore-apt-sources")
	if err != nil {
		t.Fatalf("--restore-apt-sources = %v:\n%s", err, out)
	}
	for p, want := range files {
		if got := read(p); got != want {
			t.Errorf("%s after restore:\n%q\nwant:\n%q", p, got, want)
		}
	}
	if _, err := os.Stat(aptSources.record); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("record survived a complete restore: %v", err)
	}
	out, err = runDoctor(t, "--restore-apt-sources")
	if err != nil || !strings.Contains(out, "Nothing to restore") {
		t.Errorf("second restore = %v:\n%s", err, out)
	}
}

// A record naming a file apt does not read is refused before anything runs.
func TestDoctorRestoreAptSourcesRefusesAForeignRecord(t *testing.T) {
	home := t.TempDir()
	var ran []string
	var fail error
	stubAptHost(t, home, &ran, &fail)
	if err := os.MkdirAll(filepath.Dir(aptSources.record), 0o755); err != nil {
		t.Fatal(err)
	}
	foreign := host.AptEdit{Path: "/etc/shadow.sources", Deb822: true, Units: []host.AptUnit{{
		Line: 1, Before: []string{"Types: deb\n"}, After: []string{"Enabled: no\n", "Types: deb\n"},
	}}}
	rec, _ := json.Marshal(proRecord{Steps: []string{foreign.Name()}})
	if err := os.WriteFile(aptSources.record, rec, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runDoctor(t, "--restore-apt-sources"); err == nil || !strings.Contains(err.Error(), "does not know") {
		t.Errorf("restore of a foreign record = %v", err)
	}
}

// assertNoPublicAptSource fails on any enabled source under root naming a
// public archive, by the parse the apt-sources row reads.
func assertNoPublicAptSource(t *testing.T, root string) {
	t.Helper()
	sources, err := host.AptSources(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range sources {
		if s.Public != "" {
			t.Errorf("public archive still enabled: %s:%d %s", s.File, s.Line, s.Public)
		}
	}
}

// writeAptTree writes files under root, each path unrooted.
func writeAptTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, body := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// A public stanza that sets Enabled itself is disabled like any other, and
// restores to the value it had.
func TestDoctorConfigureAptSetsAnExplicitEnabledToNo(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	const explicit = "Types: deb\nEnabled: yes\nURIs: http://archive.ubuntu.com/ubuntu/\nSuites: resolute\nComponents: main\n"
	writeAptTree(t, home, map[string]string{"/etc/apt/sources.list.d/ubuntu.sources": explicit})
	var ran []string
	var fail error
	stubAptHost(t, home, &ran, &fail)
	srv := aptPlanServer(t)
	out, err := runDoctor(t, "--configure", "apt", "--apply", "--url", srv.URL, "--allow-plaintext")
	if err != nil || !strings.Contains(out, "ubuntu.sources:1  http://archive.ubuntu.com/ubuntu/ names archive.ubuntu.com; sets Enabled: no") {
		t.Fatalf("--apply = %v:\n%s", err, out)
	}
	path := filepath.Join(home, "/etc/apt/sources.list.d/ubuntu.sources")
	if b, _ := os.ReadFile(path); string(b) != strings.Replace(explicit, "Enabled: yes", "Enabled: no", 1) {
		t.Errorf("after --apply:\n%s", b)
	}
	assertNoPublicAptSource(t, home)
	if out, err := runDoctor(t, "--restore-apt-sources"); err != nil {
		t.Fatalf("restore = %v:\n%s", err, out)
	}
	if b, _ := os.ReadFile(path); string(b) != explicit {
		t.Errorf("not restored byte for byte:\n%q", b)
	}
}

// A public source added to a file doctor already edited is planned on the
// next run, and the restore undoes both runs' edits, newest first.
func TestDoctorConfigureAptReappliesToARecordedFile(t *testing.T) {
	for _, tc := range []struct{ name, path, first, added string }{
		{"one-line", "/etc/apt/sources.list",
			"deb http://archive.ubuntu.com/ubuntu/ resolute main\n",
			"deb http://security.ubuntu.com/ubuntu/ resolute-security main\n"},
		{"deb822", "/etc/apt/sources.list.d/ubuntu.sources",
			"Types: deb\nURIs: http://archive.ubuntu.com/ubuntu/\nSuites: resolute\n",
			"\nTypes: deb\nURIs: http://security.ubuntu.com/ubuntu/\nSuites: resolute-security\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeAptTree(t, root, map[string]string{tc.path: tc.first})
			h := &aptSourcesHost{goos: "linux", root: root, record: filepath.Join(root, "record.json")}
			apply := func() {
				t.Helper()
				steps, err := h.plan(nil, "https://bodega.internal")
				if err != nil || len(steps) != 1 {
					t.Fatalf("plan = %v, %v", steps, err)
				}
				if err := h.ledger().quiet(steps); err != nil {
					t.Fatal(err)
				}
			}
			apply()
			full := filepath.Join(root, tc.path)
			b, _ := os.ReadFile(full)
			beforeSecond := string(b) + tc.added
			if err := os.WriteFile(full, []byte(beforeSecond), 0o644); err != nil {
				t.Fatal(err)
			}
			apply()
			assertNoPublicAptSource(t, root)
			if steps, err := h.plan(nil, "https://bodega.internal"); err != nil || len(steps) != 0 {
				t.Errorf("third plan = %v, %v; want nothing", steps, err)
			}
			if err := h.ledger().restore(); err != nil {
				t.Fatal(err)
			}
			if b, _ := os.ReadFile(full); string(b) != tc.first+tc.added {
				t.Errorf("restore of both runs:\n%q\nwant:\n%q", b, tc.first+tc.added)
			}
			if _, err := os.Stat(h.record); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("record survived: %v", err)
			}
		})
	}
}

// A restore that cannot prove the file still holds its edit changes nothing
// and keeps the record.
func TestDoctorRestoreAptSourcesKeepsTheRecordWhenRefused(t *testing.T) {
	root := t.TempDir()
	path := "/etc/apt/sources.list.d/ubuntu.sources"
	writeAptTree(t, root, map[string]string{path: resoluteUbuntuSources})
	h := &aptSourcesHost{goos: "linux", root: root, record: filepath.Join(root, "record.json")}
	steps, err := h.plan(nil, "https://bodega.internal")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.ledger().quiet(steps); err != nil {
		t.Fatal(err)
	}
	full := filepath.Join(root, path)
	b, _ := os.ReadFile(full)
	edited := "Types: deb\nEnabled: no\nURIs: https://vendor.example/repo\nSuites: stable\n\n" + string(b)
	if err := os.WriteFile(full, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	rec, _ := os.ReadFile(h.record)
	if err := h.ledger().restore(); err == nil {
		t.Error("restore of a shifted file succeeded")
	}
	if b, _ := os.ReadFile(full); string(b) != edited {
		t.Errorf("a refused restore wrote the file:\n%s", b)
	}
	if b, _ := os.ReadFile(h.record); string(b) != string(rec) {
		t.Errorf("a refused restore changed the record:\n%s", b)
	}
}
