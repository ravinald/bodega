package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/clientconf"
	"github.com/ravinald/bodega/internal/host"
	"github.com/ravinald/bodega/internal/manifest"
	"github.com/ravinald/bodega/internal/oracletest"
)

func TestReview39AptForeignCARefusesBeforeWrites(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	clearClientEnv(t)
	stubRuntimes(t)
	var srv *httptest.Server
	var content string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /client/plan", func(w http.ResponseWriter, r *http.Request) {
		sum := sha256.Sum256([]byte(content))
		_ = json.NewEncoder(w).Encode(clientconf.Plan{Records: []clientconf.PlanRecord{{
			System: manifest.TypeApt, Action: clientconf.PlanInstall, Path: "~" + clientconf.AptSourcesPath,
			URL: srv.URL + "/client/apt", SHA256: hex.EncodeToString(sum[:]),
		}}})
	})
	mux.HandleFunc("GET /client/apt", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, content) })
	srv = httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	content = "Types: deb\nURIs: " + srv.URL + "/apt\nSuites: stable\nComponents: main\n"
	caFile := filepath.Join(home, "issuer.pem")
	foreign := filepath.Join(home, "foreign.pem")
	conf := filepath.Join(home, "etc/apt/apt.conf")
	release := filepath.Join(home, "os-release")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(99), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	foreignPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	before := "Acquire::https::CaInfo \"" + foreign + "\";\n"
	for file, body := range map[string][]byte{caFile: caPEM, foreign: foreignPEM, conf: []byte(before), release: []byte("ID=ubuntu\n")} {
		if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	oldOS, oldRoot, oldRelease, oldRun, oldProbe, oldApt := doctorCAGOOS, doctorOCIRoot, doctorOSRelease, doctorRun, doctorTrustProbe, aptSources
	doctorCAGOOS, doctorOCIRoot, doctorOSRelease = clientconf.OSLinux, home, release
	aptSources = &aptSourcesHost{goos: "linux", root: home, record: filepath.Join(home, "apt-ledger.json")}
	doctorTrustProbe = func() host.TrustProbe {
		return host.TrustProbe{Root: home, Home: home, GOOS: clientconf.OSLinux, Getenv: os.Getenv}
	}
	anchor := filepath.Join(home, "usr/local/share/ca-certificates/bodega-ca.crt")
	ran := 0
	doctorRun = func(name string, args ...string) error {
		ran++
		if name != "update-ca-certificates" {
			t.Fatalf("unexpected command: %s %v", name, args)
		}
		bundle := filepath.Join(home, "etc/ssl/certs/ca-certificates.crt")
		if err := os.MkdirAll(filepath.Dir(bundle), 0700); err != nil {
			return err
		}
		return os.WriteFile(bundle, caPEM, 0600)
	}
	t.Cleanup(func() {
		doctorCAGOOS, doctorOCIRoot, doctorOSRelease, doctorRun, doctorTrustProbe, aptSources = oldOS, oldRoot, oldRelease, oldRun, oldProbe, oldApt
	})
	for phase, apply := range [][]string{nil, {"--apply"}, {"--apply"}} {
		out, err := runDoctor(t, append([]string{"--configure", "apt", "--ca-file", caFile, "--url", srv.URL}, apply...)...)
		t.Logf("phase %d err=%v", phase, err)
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "cainfo") {
			t.Errorf("phase %d: want preflight refusal naming CAInfo, got %v", phase, err)
		}
		for _, file := range []string{anchor, filepath.Join(home, clientconf.AptSourcesPath)} {
			if _, err := os.Stat(file); !os.IsNotExist(err) {
				t.Errorf("phase %d wrote %s before refusing CAInfo: %v", phase, file, err)
			}
		}
		if ran != 0 {
			t.Errorf("phase %d ran %d rebuilds before refusal", phase, ran)
		}
		if got, _ := os.ReadFile(conf); string(got) != before {
			t.Errorf("changed CAInfo: %s", got)
		}
		if strings.Contains(out, "wrote ") {
			t.Log(out)
		}
	}
}

func TestReview39NpmGeneratedPathRefusesBeforeWrites(t *testing.T) {
	home := filepath.Join(t.TempDir(), "account${F116_CA_SUFFIX}")
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	clearClientEnv(t)
	t.Setenv("F116_CA_SUFFIX", "expanded")
	srv, caPEM, _ := caPlanServer(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	for phase, apply := range [][]string{nil, {"--apply"}, {"--apply"}} {
		out, err := runDoctor(t, append([]string{"--configure", "npm", "--ca-file", caFile, "--url", srv.URL}, apply...)...)
		t.Logf("phase %d err=%v", phase, err)
		if err == nil {
			t.Errorf("phase %d accepted a generated cafile containing npm interpolation", phase)
		}
		for _, name := range []string{".npmrc", ".config/bodega/ca.pem"} {
			if _, statErr := os.Stat(filepath.Join(home, name)); !os.IsNotExist(statErr) {
				t.Errorf("phase %d wrote %s before refusing generated cafile: %v", phase, name, err)
			}
		}
		if strings.Contains(out, "wrote ") {
			t.Log(out)
		}
	}
}

func TestReview39NativeNpmInterpolatesCAPath(t *testing.T) {
	npm := oracletest.Npm(t)
	home := t.TempDir()
	file := filepath.Join(home, ".npmrc")
	literal := filepath.Join(home, "account${F116_CA_SUFFIX}", "ca.pem")
	expanded := filepath.Join(home, "accountexpanded", "ca.pem")
	if err := os.WriteFile(file, []byte("cafile="+literal+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(npm, "config", "get", "cafile")
	cmd.Dir = home
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "NPM_CONFIG_USERCONFIG=" + file, "NPM_CONFIG_GLOBALCONFIG=" + filepath.Join(home, "none"), "F116_CA_SUFFIX=expanded"}
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	got := strings.TrimSpace(string(out))
	if got != expanded || got == literal {
		t.Fatalf("native npm cafile=%q, want expanded %q", got, expanded)
	}
	t.Logf("native npm reads %q; doctor would write %q", got, literal)
}
