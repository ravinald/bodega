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
	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/host"
)

type review42Plan struct {
	base  string
	pem   []byte
	chain []*x509.Certificate
}

func review42PlanServer(t *testing.T, system string) review42Plan {
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
	case "git":
		f = clientconf.Git(base, map[string]config.GitUpstream{"gh": {URL: "https://github.com/"}})
	case "pypi":
		f = clientconf.Pip(base)
		f.Paths[clientconf.OSLinux] = filepath.Join(os.Getenv("HOME"), "etc/pip.conf")
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
	return review42Plan{base: base, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), chain: []*x509.Certificate{leaf}}
}

func TestReview42DoctorRefusesHTTPPolicy(t *testing.T) {
	for _, system := range []string{"git", "pypi"} {
		t.Run(system, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			clearClientEnv(t)
			stubRuntimes(t)
			plan := review42PlanServer(t, system)
			plain := strings.Replace(plan.base, "https://", "http://", 1)
			ca := filepath.Join(home, "issuer.pem")
			target := filepath.Join(home, ".gitconfig")
			body := "[url \"" + plain + "/git/corp/\"]\n insteadOf = https://corp.example/\n[http]\n sslCAInfo = " + ca + "\n"
			if system == "pypi" {
				target = filepath.Join(home, "etc/pip.conf")
				body = "[global]\nextra-index-url = " + plain + "/pypi/simple/\ntrusted-host = *\n"
			}
			if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(ca, plan.pem, 0600); err != nil {
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
			for phase, apply := range [][]string{nil, {"--apply"}, {"--apply"}} {
				out, err := runDoctor(t, append([]string{"--configure", system, "--ca-file", ca, "--url", plan.base}, apply...)...)
				t.Logf("phase %d err=%v\n%s", phase, err, out)
				if err == nil {
					t.Errorf("phase %d succeeded with a non-loopback HTTP route", phase)
				} else if !strings.Contains(strings.ToLower(err.Error()), "http") && !strings.Contains(err.Error(), "trusted-host") {
					t.Errorf("phase %d refused for an unrelated reason: %v", phase, err)
				}
				if got, e := os.ReadFile(target); e != nil || string(got) != body {
					t.Errorf("phase %d wrote policy before refusal: %v\n%s", phase, e, got)
				}
				if _, e := os.Stat(filepath.Join(home, ".config/bodega/ca.pem")); !os.IsNotExist(e) {
					t.Errorf("phase %d installed a CA before refusal", phase)
				}
				if _, e := os.Stat(filepath.Join(home, "usr/local/share/bodega/ca.pem")); !os.IsNotExist(e) {
					t.Errorf("phase %d installed shared CA before refusal", phase)
				}
			}
		})
	}
}

func TestReview42OrdinaryDoctorWarnsOnHTTPPolicy(t *testing.T) {
	for _, system := range []string{"git", "pypi"} {
		t.Run(system, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			clearClientEnv(t)
			stubRuntimes(t)
			plan := review42PlanServer(t, system)
			ca := filepath.Join(home, "issuer.pem")
			plain := strings.Replace(plan.base, "https://", "http://", 1)
			path, check := filepath.Join(home, ".gitconfig"), "git-config"
			body := "[url \"" + plain + "/git/corp/\"]\n insteadOf = https://corp.example/\n[http]\n sslCAInfo = " + ca + "\n"
			if system == "pypi" {
				path, check = filepath.Join(home, ".config/pip/pip.conf"), "pip-config"
				body = "[global]\nindex-url = " + plan.base + "/pypi/simple/\nextra-index-url = " + plain + "/plain/simple/\ntrusted-host = *\ncert = " + ca + "\n"
			}
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(ca, plan.pem, 0600); err != nil {
				t.Fatal(err)
			}
			oldProbe, oldRoot, oldExit := doctorTrustProbe, doctorOCIRoot, doctorExit
			doctorOCIRoot = home
			doctorExit = func(int) {}
			doctorTrustProbe = func() host.TrustProbe {
				return host.TrustProbe{Root: home, Home: home, GOOS: clientconf.OSLinux, Getenv: os.Getenv, LookupEnv: os.LookupEnv,
					Chain: func(string) ([]*x509.Certificate, error) { return plan.chain, nil }, System: func([]*x509.Certificate, string) error { return x509.UnknownAuthorityError{} }}
			}
			t.Cleanup(func() { doctorTrustProbe, doctorOCIRoot, doctorExit = oldProbe, oldRoot, oldExit })
			out, err := runDoctor(t, "--url", plan.base)
			if err != nil {
				t.Fatal(err)
			}
			for _, line := range strings.Split(out, "\n") {
				if !strings.HasPrefix(line, check+" ") {
					continue
				}
				t.Log(line)
				f := strings.Fields(line)
				if len(f) < 2 || f[1] != "WARN" || !strings.Contains(line, "unchecked") {
					t.Errorf("ordinary doctor certified HTTP: %s", line)
				}
				return
			}
			t.Fatalf("ordinary doctor omitted %s:\n%s", check, out)
		})
	}
}
