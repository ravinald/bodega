package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/clientconf"
	"github.com/ravinald/bodega/internal/host"
)

func TestReview45MixedPlanDoesNotReuseRemovedSystemRoot(t *testing.T) {
	old := review42PlanServer(t, "pypi")
	replacement := review42PlanServer(t, "pypi")
	oldCA, err := clientconf.ParseCA(old.pem)
	if err != nil {
		t.Fatal(err)
	}
	newCA, err := clientconf.ParseCA(replacement.pem)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	home := root
	write := func(path string, data []byte) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	release := filepath.Join(root, "os-release")
	bundle := filepath.Join(root, "etc/ssl/certs/ca-certificates.crt")
	anchor := filepath.Join(root, "usr/local/share/ca-certificates/bodega-ca.crt")
	aptCA := filepath.Join(root, "apt-roots.pem")
	aptConfig := filepath.Join(root, "etc/apt/sources.list.d/bodega.sources")
	dockerConfig := filepath.Join(root, "etc/docker/daemon.json")
	dockerCA := filepath.Join(root, "etc/docker/certs.d", strings.TrimPrefix(old.base, "https://"), "ca.crt")
	write(release, []byte("ID=ubuntu\n"))
	write(bundle, oldCA.PEM)
	write(anchor, oldCA.PEM)
	write(aptCA, append(append([]byte{}, oldCA.PEM...), newCA.PEM...))
	write(aptConfig, []byte("Types: deb\nURIs: "+old.base+"/ubuntu\nSuites: noble\nComponents: main\n"))
	write(filepath.Join(root, "etc/apt/apt.conf.d/99ca"), []byte("Acquire::https::CAInfo \""+aptCA+"\";\n"))
	write(dockerConfig, []byte(clientconf.DockerDaemon(old.base, []string{"docker.io"}).Content))
	write(dockerCA, newCA.PEM)
	savedProbe, savedRoot, savedOS, savedRelease := doctorTrustProbe, doctorOCIRoot, doctorCAGOOS, doctorOSRelease
	doctorOCIRoot, doctorCAGOOS, doctorOSRelease = root, clientconf.OSLinux, release
	t.Cleanup(func() {
		doctorTrustProbe, doctorOCIRoot, doctorCAGOOS, doctorOSRelease = savedProbe, savedRoot, savedOS, savedRelease
	})
	probe := host.TrustProbe{Root: root, Home: home, GOOS: clientconf.OSLinux,
		Getenv: func(string) string { return "" },
		Chain:  func(string) ([]*x509.Certificate, error) { return old.chain, nil },
		System: func(chain []*x509.Certificate, name string) error { return host.VerifyServed(chain, name, oldCA.Certs) },
	}
	doctorTrustProbe = func() host.TrustProbe { return probe }
	records := []clientconf.PlanRecord{{System: "apt", Path: aptConfig}, {System: "oci", Path: dockerConfig}}
	owed := owedTrustChecks(records)
	t.Logf("concrete plan obligations: %v", owed)
	if err := unreadCA(owed, []string{"apt"}, old.base); err != nil {
		t.Fatalf("before rebuild control: %v", err)
	}
	var initial []clientconf.Change
	for _, rec := range records {
		data, err := os.ReadFile(rec.Path)
		if err != nil {
			t.Fatal(err)
		}
		if rec.System == "oci" {
			data = []byte(clientconf.DockerDaemon(old.base, []string{"docker.io"}).Content)
		}
		sum := sha256.Sum256(data)
		rec.SHA256 = hex.EncodeToString(sum[:])
		c, err := clientconf.NewChange(rec, data, home)
		if err != nil {
			t.Fatal(err)
		}
		initial = append(initial, c)
	}
	install, err := clientconf.AddCA(initial, newCA, clientconf.CAHost{Root: root, Home: home, GOOS: clientconf.OSLinux, Base: old.base, OSRelease: []byte("ID=ubuntu\n")})
	if err != nil {
		t.Fatalf("the native-loadable mixed plan must be admitted: %v", err)
	}
	t.Logf("CA plan system targets=%v step=%v", install.System, install.Step)
	changes := install.Changes
	if err := plannedCA(changes, owed, []string{"apt"}, old.base); err == nil || !strings.Contains(err.Error(), "oci-docker") {
		t.Errorf("proposed replacement must reject Docker's removed system root: %v", err)
	}
	if _, err := clientconf.Apply(changes, ".review45-backup"); err != nil {
		t.Fatal(err)
	}
	write(bundle, newCA.PEM)
	fresh := probe
	fresh.System = func(chain []*x509.Certificate, name string) error {
		roots, err := clientconf.SystemRoots(clientconf.CAHost{Root: root, GOOS: clientconf.OSLinux, OSRelease: []byte("ID=ubuntu\n")})
		if err != nil {
			return err
		}
		return host.VerifyServed(chain, name, roots)
	}
	verdicts, err := fresh.Judge(owed, old.base)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range verdicts {
		t.Logf("fresh client control: %+v", v)
		if v.Check == "apt-sources" && v.State != host.TrustVerified {
			t.Fatalf("apt's retained bundle must verify: %+v", v)
		}
		if v.Check == "oci-docker" && v.State != host.TrustFailed {
			t.Fatalf("Docker must reject with only the replacement issuer: %+v", v)
		}
	}
	if err := unreadCA(owed, []string{"apt"}, old.base); err == nil || !strings.Contains(err.Error(), "oci-docker") {
		t.Errorf("after rebuild reused Docker's cached removed root: %v", err)
	}
	write(bundle, oldCA.PEM)
	if err := unreadCA(owed, []string{"apt"}, old.base); err != nil {
		t.Fatalf("restored live root control: %v", err)
	}
}

func TestReview45PipUnresolvedInstallErrorRedactsPassword(t *testing.T) {
	f := review44PipSetup(t)
	const secret = "review45-password-marker"
	location := "https://review-user:" + secret + "@bödega.internal:8443/review45_demo-1.0-py3-none-any.whl"
	before := "[global]\nfind-links=" + location + "\n"
	if err := os.WriteFile(f.config, []byte(before), 0600); err != nil {
		t.Fatal(err)
	}
	for _, apply := range [][]string{nil, {"--apply"}} {
		out, err := runDoctor(t, append([]string{"--configure", "pypi", "--ca-file", f.issuer, "--url", f.base}, apply...)...)
		if err == nil || !strings.Contains(err.Error(), "find-links") || !strings.Contains(err.Error(), f.config) {
			t.Fatalf("unresolved-location control must refuse with setting and source: %v\n%s", err, out)
		}
		t.Logf("apply=%v diagnostic=%v", apply, err)
		if strings.Contains(err.Error()+out, secret) {
			t.Errorf("unresolved-location diagnostic exposes the repository password")
		}
		if got, err := os.ReadFile(f.config); err != nil || string(got) != before {
			t.Fatalf("refusal changed the original file: %v", err)
		}
	}
}

func TestReview45PipUnresolvedReportRedactsPassword(t *testing.T) {
	f := review44PipSetup(t)
	const secret = "review45-password-marker"
	file := filepath.Join(f.home, ".config/pip/pip.conf")
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		t.Fatal(err)
	}
	body := "[global]\nindex-url=" + f.base + "/pypi/simple/\ncert=" + f.issuer + "\nfind-links=https://review-user:" + secret + "@bödega.internal:8443/review45_demo-1.0-py3-none-any.whl\n"
	if err := os.WriteFile(file, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	oldExit := doctorExit
	doctorExit = func(int) {}
	t.Cleanup(func() { doctorExit = oldExit })
	out, err := runDoctor(t, "--url", f.base)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "pip-config ") {
			continue
		}
		t.Log(line)
		if !strings.Contains(line, "WARN") || !strings.Contains(line, "unchecked") || !strings.Contains(line, "find-links") {
			t.Fatalf("unresolved-location control must remain unchecked: %s", line)
		}
		if strings.Contains(out, secret) {
			t.Error("ordinary doctor exposes the repository password")
		}
		return
	}
	t.Fatal("ordinary doctor omitted pip-config")
}
