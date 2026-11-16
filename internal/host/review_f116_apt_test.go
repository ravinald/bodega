package host

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type reviewAPTRevocation struct {
	issuer        *x509.Certificate
	leaf          *x509.Certificate
	caPEM, crlPEM []byte
}

func reviewAPTRevokedLeaf(t *testing.T) reviewAPTRevocation {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(901), Subject: pkix.Name{CommonName: "review issuer"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	le := &x509.Certificate{SerialNumber: big.NewInt(902), DNSNames: []string{"bodega.internal"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, le, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	le, err = x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour), RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: le.SerialNumber, RevocationTime: now.Add(-time.Minute)}}}, ca, key)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.CheckSignatureFrom(ca); err != nil {
		t.Fatal(err)
	}
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Cmp(le.SerialNumber) != 0 {
		t.Fatal("CRL does not revoke the served leaf")
	}
	return reviewAPTRevocation{ca, le, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlDER})}
}

func TestReviewF116APTHTTPCRLIsUnchecked(t *testing.T) {
	for _, scope := range []string{"", "bodega.internal::"} {
		t.Run(scope, func(t *testing.T) {
			p, ca, base := reviewTrust(t)
			fixture := reviewAPTRevokedLeaf(t)
			p.Chain = func(string) ([]*x509.Certificate, error) { return []*x509.Certificate{fixture.leaf}, nil }
			writeTrustFile(t, ca, string(fixture.caPEM))
			crl := filepath.Join(p.Root, "corp/revocations.crl")
			writeTrustFile(t, crl, string(fixture.crlPEM))
			file := filepath.Join(p.Root, "etc/apt/apt.conf")
			writeTrustFile(t, filepath.Join(p.Root, "etc/apt/sources.list.d/bodega.sources"), "Types: deb\nURIs: "+base+"/apt\nSuites: stable\nComponents: main\n")
			writeTrustFile(t, file, "Acquire::https::CAInfo \""+ca+"\";\n")
			if v := auditState(t, p, "apt-sources", base); v.State != TrustVerified {
				t.Fatalf("control: %+v", v)
			}
			writeTrustFile(t, file, "Acquire::https::CAInfo \""+ca+"\";\nAcquire::http::"+scope+"CrlFile \"/corp/revocations.crl\";\n")
			v := auditState(t, p, "apt-sources", base)
			if v.State != TrustUnchecked || !strings.Contains(strings.ToLower(v.Detail), "crl") {
				t.Errorf("selected verdict certified inherited CRL policy: %+v", v)
			}
			row := p.Apply([]Finding{checkAptSources(p.Root, "linux")}, base)[0]
			if row.Status != StatusWarn || !strings.Contains(row.Detail, "unchecked") || !strings.Contains(strings.ToLower(row.Detail), "crl") || !strings.Contains(row.Remediation, "--ca-file") {
				t.Errorf("ordinary row certified inherited CRL policy: %+v", row)
			}
		})
	}
}
