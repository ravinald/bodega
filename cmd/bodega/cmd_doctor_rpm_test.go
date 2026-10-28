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

// rpmHostFixture stands in for a Rocky 9 host under home: its os-release, a
// yum.repos.d holding the vendor's repositories where bodega.repo lands, a
// dnf.conf path that holds nothing until a test writes it, and dnf on PATH.
// The returned function rewrites rocky.repo's enabled lines, as dnf
// config-manager would.
func rpmHostFixture(t *testing.T, home string, bins ...string) (reposDir, dnfConf string, setEnabled func(string)) {
	t.Helper()
	dir := t.TempDir()
	osRelease := filepath.Join(dir, "os-release")
	if err := os.WriteFile(osRelease, []byte("NAME=\"Rocky Linux\"\nID=\"rocky\"\nVERSION_ID=\"9.4\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	reposDir = filepath.Join(home, filepath.Dir(clientconf.RpmRepoPath))
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
	dnfConf = filepath.Join(dir, "dnf.conf")
	prevOS, prevConf, prevDirs := doctorOSRelease, doctorDnfConf, doctorYumReposDirs
	doctorOSRelease, doctorDnfConf, doctorYumReposDirs = osRelease, dnfConf, []string{reposDir}
	t.Cleanup(func() { doctorOSRelease, doctorDnfConf, doctorYumReposDirs = prevOS, prevConf, prevDirs })
	return reposDir, dnfConf, setEnabled
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
	_, _, setEnabled := rpmHostFixture(t, home, "dnf")
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
	rpmHostFixture(t, home)
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
	reposDir, _, _ := rpmHostFixture(t, t.TempDir(), "dnf")
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

// dnfReposRow runs bare doctor with args and returns its dnf-repos row.
func dnfReposRow(t *testing.T, args ...string) string {
	t.Helper()
	prevExit := doctorExit
	doctorExit = func(int) {}
	t.Cleanup(func() { doctorExit = prevExit })
	out, err := runDoctor(t, args...)
	if err != nil {
		t.Fatalf("doctor = %v:\n%s", err, out)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "dnf-repos") {
			return line
		}
	}
	t.Fatalf("no dnf-repos row:\n%s", out)
	return ""
}

// F103 R3: with no --url and no public_url, doctor has no bodega to compare
// against, so a bodega- section pointing at the vendor is reported and one
// that might be bodega's is named as unverified; neither is passed on its id.
func TestDoctorDnfReposWithNoBaseURL(t *testing.T) {
	reposDir, _, setEnabled := rpmHostFixture(t, t.TempDir(), "dnf")
	setEnabled("0")
	bodegaRepo := filepath.Join(reposDir, "bodega.repo")
	if err := os.WriteFile(bodegaRepo, []byte("[bodega-rocky-baseos]\nbaseurl=https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/\nenabled=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if row := dnfReposRow(t); !strings.Contains(row, "WARN") || !strings.Contains(row, "bodega-rocky-baseos (bodega.repo: https://dl.rockylinux.org") {
		t.Errorf("a bodega- section pointing upstream = %q", row)
	}

	if err := os.WriteFile(bodegaRepo, []byte("[bodega-rocky-baseos]\nbaseurl=https://bodega.internal/rpm/rocky-baseos/$releasever/$basearch/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if row := dnfReposRow(t); !strings.Contains(row, "SKIPPED") || !strings.Contains(row, "bodega-rocky-baseos") {
		t.Errorf("a section doctor cannot place = %q, want SKIPPED naming it", row)
	}
	if row := dnfReposRow(t, "--url", "https://bodega.internal"); !strings.Contains(row, "OK") {
		t.Errorf("the same section against its own bodega = %q", row)
	}
}

// F103 R2, R3: doctor reads dnf.conf's own repository sections and the
// reposdir it sets, a quoted enabled counts as enabled, and the dnf step
// disables a vendor repository dnf.conf defines.
func TestDoctorDnfReposFollowDnfConf(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	reposDir, dnfConf, setEnabled := rpmHostFixture(t, home, "dnf")
	setEnabled("0")
	custom := filepath.Join(t.TempDir(), "custom.repos.d")
	if err := os.MkdirAll(custom, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(custom, "ext.repo"), []byte("[ext]\nmirrorlist=https://mirror.example/list\nenabled=\"1\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeConf := func(reposdir string) {
		t.Helper()
		body := "[main]\nreposdir=" + reposdir + "\n\n[baseos]\nname=Rocky BaseOS\nbaseurl=https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/\nenabled=\"1\"\n"
		if err := os.WriteFile(dnfConf, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeConf(reposDir + "," + custom)

	row := dnfReposRow(t, "--url", "https://bodega.internal")
	if !strings.Contains(row, "WARN") || !strings.Contains(row, "baseos (dnf.conf:") || !strings.Contains(row, "ext (ext.repo: https://mirror.example/list)") {
		t.Errorf("dnf-repos row = %q", row)
	}

	var ran [][]string
	prevRun := doctorRun
	doctorRun = func(name string, args ...string) error {
		ran = append(ran, append([]string{name}, args...))
		return nil
	}
	t.Cleanup(func() { doctorRun = prevRun })
	srv, _ := rpmPlanServer(t)
	out, err := runDoctor(t, "--configure", "rpm", "--url", srv.URL, "--allow-plaintext", "--apply")
	if err != nil || len(ran) != 1 || !slices.Equal(ran[0], strings.Fields("dnf config-manager --set-disabled baseos")) {
		t.Fatalf("--apply = %v, ran %v:\n%s", err, ran, out)
	}

	if err := os.Remove(filepath.Join(home, clientconf.RpmRepoPath)); err != nil {
		t.Fatal(err)
	}
	writeConf(custom)
	ran = nil
	_, err = runDoctor(t, "--configure", "rpm", "--url", srv.URL, "--allow-plaintext", "--apply")
	if err == nil || !strings.Contains(err.Error(), "dnf would never read") || len(ran) != 0 {
		t.Errorf("--apply with reposdir leaving out yum.repos.d = %v, ran %v", err, ran)
	}
	if _, err := os.Stat(filepath.Join(home, clientconf.RpmRepoPath)); err == nil {
		t.Error("bodega.repo was written where dnf's reposdir does not look")
	}
}
