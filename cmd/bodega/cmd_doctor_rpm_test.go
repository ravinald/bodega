package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/clientconf"
	"github.com/ravinald/bodega/internal/manifest"
)

const rockyRepo = `[baseos]
name=Rocky Linux $releasever - BaseOS
mirrorlist=https://mirrors.rockylinux.org/mirrorlist?arch=$basearch&repo=BaseOS-$releasever
enabled=%s

[appstream]
name=Rocky Linux $releasever - AppStream
mirrorlist=https://mirrors.rockylinux.org/mirrorlist?arch=$basearch&repo=AppStream-$releasever
enabled=%s
`

// rpmHostFixture stands in for a Rocky 9 host: its os-release, a
// yum.repos.d holding the vendor's repositories, and dnf on PATH. The
// returned function rewrites rocky.repo's enabled lines, as dnf
// config-manager would.
func rpmHostFixture(t *testing.T, bins ...string) (reposDir string, setEnabled func(string)) {
	t.Helper()
	dir := t.TempDir()
	osRelease := filepath.Join(dir, "os-release")
	if err := os.WriteFile(osRelease, []byte("NAME=\"Rocky Linux\"\nID=\"rocky\"\nVERSION_ID=\"9.4\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	reposDir = filepath.Join(dir, "yum.repos.d")
	if err := os.MkdirAll(reposDir, 0o755); err != nil {
		t.Fatal(err)
	}
	setEnabled = func(v string) {
		if err := os.WriteFile(filepath.Join(reposDir, "rocky.repo"), []byte(strings.ReplaceAll(rockyRepo, "%s", v)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	setEnabled("1")
	stubRuntimes(t, bins...)
	prevOS, prevDirs := doctorOSRelease, doctorYumReposDirs
	doctorOSRelease, doctorYumReposDirs = osRelease, []string{reposDir}
	t.Cleanup(func() { doctorOSRelease, doctorYumReposDirs = prevOS, prevDirs })
	return reposDir, setEnabled
}

// rpmPlanServer answers /client/plan as a server configuring Rocky's BaseOS
// and AppStream and not EPEL does, the paths rooted under the caller's home.
func rpmPlanServer(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	d, _ := clientconf.RpmDistroFor("rocky", "9.4")
	repo, _ := clientconf.RpmHost("https://bodega.internal", d, func(up string) bool { return up != "epel" })
	files := map[string]string{
		"/client/rpm":     repo.Content,
		"/rpm/bodega.gpg": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nbodega\n-----END PGP PUBLIC KEY BLOCK-----\n",
	}
	var queries []string
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("GET /client/plan", func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.RawQuery)
		var plan clientconf.Plan
		for _, rec := range [][2]string{{clientconf.RpmRepoPath, "/client/rpm"}, {clientconf.RpmKeyPath, "/rpm/bodega.gpg"}} {
			sum := sha256.Sum256([]byte(files[rec[1]]))
			plan.Records = append(plan.Records, clientconf.PlanRecord{
				Identity: "rocky-host", Match: "cidr:192.0.2.1/32", System: manifest.TypeRpm, Action: clientconf.PlanInstall,
				Path: "~" + rec[0], URL: srv.URL + rec[1], SHA256: hex.EncodeToString(sum[:]), Reason: strings.Join(repo.Notes, ". "),
			})
		}
		_ = json.NewEncoder(w).Encode(plan)
	})
	for route, body := range files {
		mux.HandleFunc("GET "+route, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, body) })
	}
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &queries
}

// F103 R1, R2: the dry run prints bodega.repo, the key and the dnf step and
// runs nothing; --apply writes both files and disables the vendor
// repositories bodega.repo replaces; once they are off a second --apply
// changes nothing.
func TestDoctorConfigureRpmWritesTheRepoAndDisablesTheVendors(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	_, setEnabled := rpmHostFixture(t, "dnf")
	var ran [][]string
	prevRun := doctorRun
	doctorRun = func(name string, args ...string) error {
		ran = append(ran, append([]string{name}, args...))
		return nil
	}
	t.Cleanup(func() { doctorRun = prevRun })
	srv, queries := rpmPlanServer(t)
	const step = "dnf config-manager --set-disabled baseos appstream"

	out, err := runDoctor(t, "--configure", "rpm", "--url", srv.URL, "--allow-plaintext")
	if err != nil || !strings.Contains(out, step) || !strings.Contains(out, "epel is left out") || !strings.Contains(out, "Dry run") {
		t.Fatalf("dry run = %v:\n%s", err, out)
	}
	if len(ran) != 0 {
		t.Errorf("the dry run ran %v", ran)
	}
	if q := (*queries)[0]; !strings.Contains(q, "os_id=rocky") || !strings.Contains(q, "os_version_id=9.4") {
		t.Errorf("the plan request did not state the distribution: %s", q)
	}

	out, err = runDoctor(t, "--configure", "rpm", "--url", srv.URL, "--allow-plaintext", "--apply")
	if err != nil {
		t.Fatalf("--apply = %v:\n%s", err, out)
	}
	if len(ran) != 1 || !slices.Equal(ran[0], strings.Fields(step)) {
		t.Errorf("--apply ran %v, want %q", ran, step)
	}
	repo, _ := os.ReadFile(filepath.Join(home, clientconf.RpmRepoPath))
	if !strings.Contains(string(repo), "[bodega-rocky-baseos]") || strings.Contains(string(repo), "epel") {
		t.Errorf("bodega.repo = %s", repo)
	}
	if _, err := os.Stat(filepath.Join(home, clientconf.RpmKeyPath)); err != nil {
		t.Errorf("the key was not written: %v", err)
	}

	setEnabled("0")
	out, err = runDoctor(t, "--configure", "rpm", "--url", srv.URL, "--allow-plaintext", "--apply")
	if err != nil || !strings.Contains(out, "Nothing to change") || len(ran) != 1 {
		t.Errorf("second --apply = %v, ran %v:\n%s", err, ran, out)
	}
}

// F103 R1: rpm named on a host with no dnf is refused before anything is
// written.
func TestDoctorConfigureRpmRefusesWithNoDnf(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	rpmHostFixture(t)
	srv, _ := rpmPlanServer(t)
	_, err := runDoctor(t, "--configure", "rpm", "--url", srv.URL, "--allow-plaintext", "--apply")
	if err == nil || !strings.Contains(err.Error(), "dnf is not on PATH") {
		t.Errorf("--configure rpm with no dnf = %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, clientconf.RpmRepoPath)); err == nil {
		t.Error("bodega.repo was written on a host with no dnf")
	}
}

// F103 R3: bare doctor on a dnf host names every enabled repository that
// fetches around bodega, and the command that configures it; a disabled
// one and bodega's own are not named, and a host with no dnf gets no row.
func TestDoctorReportsDnfRepositoriesAroundBodega(t *testing.T) {
	reposDir, _ := rpmHostFixture(t, "dnf")
	if err := os.WriteFile(filepath.Join(reposDir, "epel.repo"), []byte("[epel]\nmetalink=https://mirrors.fedoraproject.org/metalink?repo=epel-$releasever\nenabled=0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(reposDir, "bodega.repo"), []byte("[bodega-rocky-baseos]\nbaseurl=https://bodega.internal/rpm/rocky-baseos/$releasever/$basearch/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	prevExit := doctorExit
	doctorExit = func(int) {}
	t.Cleanup(func() { doctorExit = prevExit })

	out, err := runDoctor(t, "--url", "https://bodega.internal")
	if err != nil {
		t.Fatalf("doctor = %v:\n%s", err, out)
	}
	var row string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "dnf-repos") {
			row = line
		}
	}
	if !strings.Contains(row, "WARN") || !strings.Contains(row, "baseos (rocky.repo") || !strings.Contains(row, "appstream (rocky.repo") {
		t.Errorf("dnf-repos row = %q", row)
	}
	if strings.Contains(row, "epel") || strings.Contains(row, "bodega-rocky-baseos") {
		t.Errorf("dnf-repos named a disabled or bodega repository: %q", row)
	}
	if !strings.Contains(out, "bodega doctor --configure rpm --apply") {
		t.Errorf("the remediation does not name --configure rpm:\n%s", out)
	}

	stubRuntimes(t)
	out, _ = runDoctor(t, "--url", "https://bodega.internal")
	if strings.Contains(out, "dnf-repos") {
		t.Errorf("a host with no dnf got a dnf-repos row:\n%s", out)
	}
}
