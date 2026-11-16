package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/clientconf"
	"github.com/ravinald/bodega/internal/host"
)

type review41Plan struct {
	base  string
	pem   []byte
	chain []*x509.Certificate
}

func review41PlanServer(t *testing.T, system string) review41Plan {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	issuer := &x509.Certificate{SerialNumber: big.NewInt(901), Subject: pkix.Name{CommonName: "review issuer"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, issuer, issuer, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(902), DNSNames: []string{"bodega.internal"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, issuer, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err = x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	var base string
	var f clientconf.File
	mux := http.NewServeMux()
	mux.HandleFunc("GET /client/plan", func(w http.ResponseWriter, r *http.Request) {
		sum := sha256.Sum256([]byte(f.Content))
		_ = json.NewEncoder(w).Encode(clientconf.Plan{Records: []clientconf.PlanRecord{{System: system, Action: clientconf.PlanInstall, Path: f.Path(clientconf.OSLinux), URL: base + "/client/file", SHA256: hex.EncodeToString(sum[:])}}})
	})
	mux.HandleFunc("GET /client/file", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, f.Content) })
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	base = "https://bodega.internal:" + port
	switch system {
	case "npm":
		f = clientconf.Npm(base, nil)
	case "helm":
		f = clientconf.Helm(base)
	}
	old := http.DefaultTransport
	tr := old.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	http.DefaultTransport = tr
	t.Cleanup(func() { http.DefaultTransport = old; tr.CloseIdleConnections() })
	return review41Plan{base: base, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), chain: []*x509.Certificate{leaf}}
}

func TestReview41DoctorRefusesRetainedPlaintextEndpoint(t *testing.T) {
	for _, system := range []string{"npm", "helm"} {
		t.Run(system, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			clearClientEnv(t)
			stubRuntimes(t)
			plan := review41PlanServer(t, system)
			plain := strings.Replace(plan.base, "https://", "http://", 1)
			name, body := ".npmrc", "@plain:registry="+plain+"/npm/\n"
			if system == "helm" {
				name = ".config/helm/repositories.yaml"
				body = "repositories:\n- name: plain\n  url: " + plain + "/helm\n"
			}
			target := filepath.Join(home, name)
			caFile, release := filepath.Join(home, "issuer.pem"), filepath.Join(home, "os-release")
			for f, b := range map[string][]byte{target: []byte(body), caFile: plan.pem, release: []byte("ID=ubuntu\n")} {
				if err := os.MkdirAll(filepath.Dir(f), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(f, b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			oldOS, oldRoot, oldRelease, oldRun, oldProbe := doctorCAGOOS, doctorOCIRoot, doctorOSRelease, doctorRun, doctorTrustProbe
			doctorCAGOOS, doctorOCIRoot, doctorOSRelease = clientconf.OSLinux, home, release
			doctorTrustProbe = func() host.TrustProbe {
				return host.TrustProbe{Root: home, Home: home, GOOS: clientconf.OSLinux, Getenv: os.Getenv, LookupEnv: os.LookupEnv, Chain: func(string) ([]*x509.Certificate, error) { return plan.chain, nil }, System: func(c []*x509.Certificate, n string) error {
					roots, _ := clientconf.SystemRoots(clientconf.CAHost{Root: home, GOOS: clientconf.OSLinux, OSRelease: []byte("ID=ubuntu\n")})
					return host.VerifyServed(c, n, roots)
				}}
			}
			ran := 0
			doctorRun = func(command string, args ...string) error {
				ran++
				if command != "update-ca-certificates" {
					t.Fatalf("unexpected command: %s %v", command, args)
				}
				bundle := filepath.Join(home, "etc/ssl/certs/ca-certificates.crt")
				if err := os.MkdirAll(filepath.Dir(bundle), 0700); err != nil {
					return err
				}
				return os.WriteFile(bundle, plan.pem, 0600)
			}
			t.Cleanup(func() {
				doctorCAGOOS, doctorOCIRoot, doctorOSRelease, doctorRun, doctorTrustProbe = oldOS, oldRoot, oldRelease, oldRun, oldProbe
			})
			for phase, apply := range [][]string{nil, {"--apply"}, {"--apply"}} {
				out, err := runDoctor(t, append([]string{"--configure", system, "--ca-file", caFile, "--url", plan.base}, apply...)...)
				t.Logf("phase %d: err=%v\n%s", phase, err, out)
				if err == nil || !strings.Contains(strings.ToLower(err.Error()), "http") {
					t.Errorf("phase %d accepted a retained plaintext endpoint; want refusal naming its transport", phase)
				}
				if got, err := os.ReadFile(target); err != nil || string(got) != body {
					t.Errorf("phase %d changed configuration before refusing plaintext: %v\n%s", phase, err, got)
				}
				for _, name := range []string{".config/bodega/ca.pem", "usr/local/share/ca-certificates/bodega-ca.crt"} {
					if _, err := os.Stat(filepath.Join(home, name)); !os.IsNotExist(err) {
						t.Errorf("phase %d wrote %s before refusing plaintext", phase, name)
					}
				}
				if ran != 0 {
					t.Errorf("phase %d rebuilt the trust store %d times before refusal", phase, ran)
				}
			}
		})
	}
}

func TestReview41OrdinaryDoctorWarnsOnPlaintextRepository(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	clearClientEnv(t)
	stubRuntimes(t)
	plan := review41PlanServer(t, "helm")
	file := filepath.Join(home, ".config/helm/repositories.yaml")
	ca := filepath.Join(home, "issuer.pem")
	if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ca, plan.pem, 0600); err != nil {
		t.Fatal(err)
	}
	plain := strings.Replace(plan.base, "https://", "http://", 1)
	body := "repositories:\n- name: plain\n  url: " + plain + "/helm\n  caFile: " + ca + "\n- name: secure\n  url: " + plan.base + "/helm\n  caFile: " + ca + "\n"
	if err := os.WriteFile(file, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	oldProbe, oldExit, oldRoot := doctorTrustProbe, doctorExit, doctorOCIRoot
	doctorExit = func(int) {}
	doctorOCIRoot = home
	doctorTrustProbe = func() host.TrustProbe {
		return host.TrustProbe{Root: home, Home: home, GOOS: clientconf.OSLinux, Getenv: os.Getenv, LookupEnv: os.LookupEnv,
			Chain:  func(string) ([]*x509.Certificate, error) { return plan.chain, nil },
			System: func([]*x509.Certificate, string) error { return x509.UnknownAuthorityError{} }}
	}
	t.Cleanup(func() { doctorTrustProbe, doctorExit, doctorOCIRoot = oldProbe, oldExit, oldRoot })
	out, err := runDoctor(t, "--url", plan.base)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "helm-repos ") {
			t.Log(line)
			fields := strings.Fields(line)
			if len(fields) < 2 || fields[1] != "WARN" || !strings.Contains(line, "unchecked") {
				t.Errorf("ordinary doctor certified a retained HTTP repository: %s", line)
			}
			return
		}
	}
	t.Fatalf("ordinary doctor omitted Helm's obligation:\n%s", out)
}
