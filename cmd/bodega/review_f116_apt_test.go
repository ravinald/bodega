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
	"github.com/ravinald/bodega/internal/manifest"
)

func TestReviewF116APTHTTPCRLRefusesDoctorBeforeWrites(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	clearClientEnv(t)
	stubRuntimes(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	issuer := &x509.Certificate{SerialNumber: big.NewInt(601), Subject: pkix.Name{CommonName: "review issuer"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, issuer, issuer, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(602), DNSNames: []string{"bodega.internal"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, issuer, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour), RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: leaf.SerialNumber, RevocationTime: now.Add(-time.Minute)}}}, issuer, key)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		t.Fatal(err)
	}
	var base, content string
	mux := http.NewServeMux()
	mux.HandleFunc("GET /client/plan", func(w http.ResponseWriter, r *http.Request) {
		sum := sha256.Sum256([]byte(content))
		_ = json.NewEncoder(w).Encode(clientconf.Plan{Records: []clientconf.PlanRecord{{System: manifest.TypeApt, Action: clientconf.PlanInstall, Path: "~" + clientconf.AptSourcesPath, URL: base + "/client/apt", SHA256: hex.EncodeToString(sum[:])}}})
	})
	mux.HandleFunc("GET /client/apt", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, content) })
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	base = "https://bodega.internal:" + port
	content = "Types: deb\nURIs: " + base + "/apt\nSuites: stable\nComponents: main\n"
	oldTransport := http.DefaultTransport
	tr := oldTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
	}
	http.DefaultTransport = tr
	t.Cleanup(func() { http.DefaultTransport = oldTransport; tr.CloseIdleConnections() })
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caFile, release := filepath.Join(home, "issuer.pem"), filepath.Join(home, "os-release")
	conf := filepath.Join(home, "etc/apt/apt.conf")
	before := "Acquire::http::CrlFile \"/corp/revocations.crl\";\n"
	for file, body := range map[string][]byte{caFile: caPEM, release: []byte("ID=ubuntu\n"), conf: []byte(before), filepath.Join(home, "corp/revocations.crl"): pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})} {
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
		return host.TrustProbe{Root: home, Home: home, GOOS: clientconf.OSLinux, Getenv: os.Getenv, LookupEnv: os.LookupEnv, Chain: func(string) ([]*x509.Certificate, error) {
			conn, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{ServerName: "bodega.internal", InsecureSkipVerify: true}) //nolint:gosec // reads the chain the server presents, unverified on purpose
			if err != nil {
				return nil, err
			}
			defer func() { _ = conn.Close() }()
			return conn.ConnectionState().PeerCertificates, nil
		}}
	}
	ran := 0
	doctorRun = func(name string, args ...string) error {
		ran++
		if name != "update-ca-certificates" {
			t.Fatalf("unexpected command %s %v", name, args)
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
		out, err := runDoctor(t, append([]string{"--configure", "apt", "--ca-file", caFile, "--url", base}, apply...)...)
		if err == nil || !strings.Contains(strings.ToLower(err.Error()), "crl") {
			t.Errorf("phase %d certified an APT policy that revokes the served leaf: err=%v\n%s", phase, err, out)
		}
		for _, file := range []string{filepath.Join(home, clientconf.AptSourcesPath), filepath.Join(home, "usr/local/share/ca-certificates/bodega-ca.crt")} {
			if _, err := os.Stat(file); !os.IsNotExist(err) {
				t.Errorf("phase %d wrote %s before refusing inherited CRL: %v", phase, file, err)
			}
		}
		if ran != 0 {
			t.Errorf("phase %d ran %d rebuilds before refusal", phase, ran)
		}
		if got, err := os.ReadFile(conf); err != nil || string(got) != before {
			t.Errorf("changed CRL policy: %v %s", err, got)
		}
	}
}
