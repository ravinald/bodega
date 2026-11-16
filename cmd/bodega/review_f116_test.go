package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/oracletest"
)

func TestReviewF116ForeignTrustEnvironmentRefusesBeforeWrites(t *testing.T) {
	for _, tc := range []struct{ system, key, config string }{
		{"pypi", "PIP_CERT", "etc/pip.conf"},
		{"pypi", "REQUESTS_CA_BUNDLE", "etc/pip.conf"},
		{"pypi", "CURL_CA_BUNDLE", "etc/pip.conf"},
		{"git", "GIT_SSL_CAINFO", ".gitconfig"},
	} {
		t.Run(tc.key, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			clearClientEnv(t)
			srv, caPEM, _ := caPlanServer(t)
			caFile := filepath.Join(t.TempDir(), "ca.pem")
			if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
				t.Fatal(err)
			}
			foreign := filepath.Join(t.TempDir(), "foreign.pem")
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			cert := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "unrelated corporate CA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
			der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(foreign, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv(tc.key, foreign)
			out, err := runDoctor(t, "--configure", tc.system, "--ca-file", caFile, "--url", srv.URL, "--apply")
			if err == nil || !strings.Contains(err.Error(), tc.key) {
				t.Errorf("want refusal naming %s, got %v\n%s", tc.key, err, out)
			}
			for _, name := range []string{tc.config, ".config/bodega/ca.pem"} {
				if _, statErr := os.Stat(filepath.Join(home, name)); !os.IsNotExist(statErr) {
					t.Errorf("wrote %s before refusing effective %s: err=%v\n%s", name, tc.key, err, out)
				}
			}
		})
	}
}

func TestReviewF116NpmCAPathDecodedBeforeWrites(t *testing.T) {
	home := filepath.Join(t.TempDir(), "account#corp")
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	clearClientEnv(t)
	srv, caPEM, _ := caPlanServer(t)
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
		t.Fatal(err)
	}
	out, err := runDoctor(t, "--configure", "npm", "--ca-file", caFile, "--url", srv.URL, "--apply")
	if err == nil {
		return
	}
	for _, name := range []string{".npmrc", ".config/bodega/ca.pem"} {
		if _, statErr := os.Stat(filepath.Join(home, name)); !os.IsNotExist(statErr) {
			t.Errorf("CA path was not decoded until after writing %s: %v\n%s", name, err, out)
		}
	}
}

func TestReviewF116NpmNativeReadsWrittenCAPath(t *testing.T) {
	npm := oracletest.Npm(t)
	for _, mark := range []string{"#", ";"} {
		t.Run(mark, func(t *testing.T) {
			home := filepath.Join(t.TempDir(), "account"+mark+"corp")
			if err := os.MkdirAll(home, 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("HOME", home)
			clearClientEnv(t)
			srv, caPEM, _ := caPlanServer(t)
			caFile := filepath.Join(t.TempDir(), "ca.pem")
			if err := os.WriteFile(caFile, caPEM, 0600); err != nil {
				t.Fatal(err)
			}
			_, applyErr := runDoctor(t, "--configure", "npm", "--ca-file", caFile, "--url", srv.URL, "--apply")
			config := filepath.Join(home, ".npmrc")
			if _, err := os.Stat(config); os.IsNotExist(err) && applyErr != nil {
				return
			}
			native := exec.Command(npm, "config", "get", "cafile")
			native.Dir = t.TempDir()
			native.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "npm_config_userconfig=" + config, "npm_config_globalconfig=" + os.DevNull}
			out, err := native.Output()
			if err != nil {
				t.Fatal(err)
			}
			want := filepath.Join(home, ".config/bodega/ca.pem")
			if got := strings.TrimSpace(string(out)); got != want {
				t.Errorf("native npm reads %q; installed CA is %q (apply: %v)", got, want, applyErr)
			}
		})
	}
}
