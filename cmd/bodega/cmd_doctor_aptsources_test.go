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
	if b, err := os.ReadFile(aptSources.record); err != nil || json.Unmarshal(b, &rec) != nil ||
		len(rec.Steps) != 1 || rec.Steps[0] != "deb822 /etc/apt/sources.list.d/ubuntu.sources 3,11" {
		t.Errorf("record = %+v (%v)", rec, err)
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
	if err := os.WriteFile(aptSources.record, []byte(`{"steps":["deb822 /etc/shadow.sources 1"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := runDoctor(t, "--restore-apt-sources"); err == nil || !strings.Contains(err.Error(), "does not know") {
		t.Errorf("restore of a foreign record = %v", err)
	}
}
