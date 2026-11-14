package main

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ravinald/bodega/internal/clientconf"
	"github.com/ravinald/bodega/internal/host"
)

type review44Pip struct {
	home, config, issuer, base string
	chain                      []*x509.Certificate
}

func review44PipSetup(t *testing.T) review44Pip {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	clearClientEnv(t)
	stubRuntimes(t)
	plan := review42PlanServer(t, "pypi")
	f := review44Pip{home, filepath.Join(home, "etc/pip.conf"), filepath.Join(home, "issuer.pem"), plan.base, plan.chain}
	if err := os.MkdirAll(filepath.Dir(f.config), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.issuer, plan.pem, 0600); err != nil {
		t.Fatal(err)
	}
	oldProbe, oldRoot, oldOS := doctorTrustProbe, doctorOCIRoot, doctorCAGOOS
	doctorOCIRoot, doctorCAGOOS = home, clientconf.OSLinux
	doctorTrustProbe = func() host.TrustProbe {
		return host.TrustProbe{Root: home, Home: home, GOOS: clientconf.OSLinux, Getenv: os.Getenv, LookupEnv: os.LookupEnv,
			Chain:  func(string) ([]*x509.Certificate, error) { return plan.chain, nil },
			System: func([]*x509.Certificate, string) error { return x509.UnknownAuthorityError{} }}
	}
	t.Cleanup(func() { doctorTrustProbe, doctorOCIRoot, doctorCAGOOS = oldProbe, oldRoot, oldOS })
	return f
}

func TestReview44DoctorRefusesPipFindLinksHTTP(t *testing.T) {
	f := review44PipSetup(t)
	before := "[global]\nfind-links=" + strings.Replace(strings.Replace(f.base, "https://", "http://", 1), "bodega.internal", "bodega%2einternal", 1) + "/review43_demo-1.0-py3-none-any.whl\n"
	if err := os.WriteFile(f.config, []byte(before), 0600); err != nil {
		t.Fatal(err)
	}
	for phase, apply := range [][]string{nil, {"--apply"}, {"--apply"}} {
		out, err := runDoctor(t, append([]string{"--configure", "pypi", "--ca-file", f.issuer, "--url", f.base}, apply...)...)
		t.Logf("phase=%d err=%v\n%s", phase, err, out)
		if err == nil || !strings.Contains(err.Error(), "find-links") {
			t.Errorf("phase %d must refuse the HTTP wheel before writing, naming find-links", phase)
		}
		if got, e := os.ReadFile(f.config); e != nil || string(got) != before {
			t.Errorf("phase %d changed policy before refusal: %v\n%s", phase, e, got)
		}
		if _, e := os.Stat(filepath.Join(f.home, "usr/local/share/bodega/ca.pem")); !os.IsNotExist(e) {
			t.Errorf("phase %d installed a CA before refusal: %v", phase, e)
		}
	}
}

func TestReview44DoctorIdleRefusesPipFindLinksHTTP(t *testing.T) {
	f := review44PipSetup(t)
	args := []string{"--configure", "pypi", "--ca-file", f.issuer, "--url", f.base, "--apply"}
	if out, err := runDoctor(t, args...); err != nil {
		t.Fatalf("HTTPS control: %v\n%s", err, out)
	}
	before, err := os.ReadFile(f.config)
	if err != nil {
		t.Fatal(err)
	}
	before = append(before, []byte("find-links="+strings.Replace(strings.Replace(f.base, "https://", "http://", 1), "bodega.internal", "bodega%2einternal", 1)+"/review43_demo-1.0-py3-none-any.whl\n")...)
	if err := os.WriteFile(f.config, before, 0600); err != nil {
		t.Fatal(err)
	}
	out, err := runDoctor(t, args...)
	t.Logf("idle err=%v\n%s", err, out)
	if err == nil || !strings.Contains(err.Error(), "find-links") {
		t.Error("idle apply certified the added HTTP wheel route")
	}
	if got, e := os.ReadFile(f.config); e != nil || string(got) != string(before) {
		t.Errorf("idle apply changed policy before refusal: %v\n%s", e, got)
	}
}

func TestReview44OrdinaryDoctorWarnsOnPipFindLinksHTTP(t *testing.T) {
	f := review44PipSetup(t)
	file := filepath.Join(f.home, ".config/pip/pip.conf")
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		t.Fatal(err)
	}
	body := "[global]\nindex-url=" + f.base + "/pypi/simple/\ncert=" + f.issuer + "\nfind-links=" + strings.Replace(strings.Replace(f.base, "https://", "http://", 1), "bodega.internal", "bodega%2einternal", 1) + "/review43_demo-1.0-py3-none-any.whl\n"
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
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[1] != "WARN" || !strings.Contains(line, "unchecked") || !strings.Contains(line, "find-links") {
			t.Errorf("ordinary doctor certified a direct HTTP wheel: %s", line)
		}
		return
	}
	t.Fatal("ordinary doctor omitted pip-config")
}

func TestReview44RebuiltStoreDoesNotReuseRemovedRoot(t *testing.T) {
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
	release := filepath.Join(root, "os-release")
	bundle := filepath.Join(root, "etc/ssl/certs/ca-certificates.crt")
	if err := os.MkdirAll(filepath.Dir(bundle), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(release, []byte("ID=ubuntu\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundle, newCA.PEM, 0600); err != nil {
		t.Fatal(err)
	}
	savedProbe, savedRoot, savedOS, savedRelease := doctorTrustProbe, doctorOCIRoot, doctorCAGOOS, doctorOSRelease
	doctorOCIRoot, doctorCAGOOS, doctorOSRelease = root, clientconf.OSLinux, release
	t.Cleanup(func() {
		doctorTrustProbe, doctorOCIRoot, doctorCAGOOS, doctorOSRelease = savedProbe, savedRoot, savedOS, savedRelease
	})
	doctorTrustProbe = func() host.TrustProbe {
		return host.TrustProbe{Root: root, GOOS: clientconf.OSLinux,
			Getenv: func(key string) string {
				if key == "GOPROXY" {
					return old.base + "/go/"
				}
				return ""
			},
			Chain:  func(string) ([]*x509.Certificate, error) { return old.chain, nil },
			System: func(chain []*x509.Certificate, name string) error { return host.VerifyServed(chain, name, oldCA.Certs) },
		}
	}
	if err := host.VerifyServed(old.chain, "bodega.internal", doctorRebuiltRoots()); err == nil {
		t.Fatal("the rebuilt-store control unexpectedly trusts the old issuer")
	}
	if err := host.VerifyServed(old.chain, "bodega.internal", oldCA.Certs); err != nil {
		t.Fatalf("the cached-store control must trust the old issuer: %v", err)
	}
	for _, phase := range []string{"after rebuild"} {
		err := unreadCA([]string{"goproxy-env"}, []string{"gomod"}, old.base)
		t.Logf("%s: live bundle rejects old issuer; unreadCA=%v", phase, err)
		if err == nil || !strings.Contains(err.Error(), "gomod") {
			t.Errorf("%s reused the process's removed root instead of the client's live bundle: %v", phase, err)
		}
	}
	if err := os.WriteFile(bundle, oldCA.PEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := unreadCA([]string{"goproxy-env"}, []string{"gomod"}, old.base); err != nil {
		t.Fatalf("a live bundle holding the served issuer must pass: %v", err)
	}
}
