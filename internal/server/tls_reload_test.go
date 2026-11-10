package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/config"
)

// WriteTestCertPair writes a self-signed P-256 leaf for 127.0.0.1 to the two
// paths, replacing what is there. The common name is how a test tells one
// certificate from the next. Exported for the external test package.
func WriteTestCertPair(t testing.TB, certPath, keyPath, commonName string, notAfter time.Time) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		Issuer:       pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	for path, block := range map[string]*pem.Block{
		certPath: {Type: "CERTIFICATE", Bytes: der},
		keyPath:  {Type: "EC PRIVATE KEY", Bytes: keyDER},
	} {
		if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
}

// ServedCommonName completes a handshake with addr and returns the common
// name of the certificate it was handed, or "" when the handshake failed.
// Verification is off: the question is which certificate the server presents,
// and an expired one has to be readable to be reported.
func ServedCommonName(addr string) string {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr,
		&tls.Config{InsecureSkipVerify: true}) //nolint:gosec // self-signed fixture
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }()
	return conn.ConnectionState().PeerCertificates[0].Subject.CommonName
}

type certFixture struct {
	s             *Server
	addr          string
	cert, key     string
	logs          *syncBuffer
	sig           chan os.Signal
	reloadsLogged int
}

// startCertServer starts a TLS server presenting a certificate named
// "loaded". poll is the stat interval; zero leaves the one-minute default, so
// only a signal reloads within the life of a test.
func startCertServer(t *testing.T, poll time.Duration) *certFixture {
	t.Helper()
	dir := t.TempDir()
	f := &certFixture{
		addr: reservePort(t),
		cert: filepath.Join(dir, "cert.pem"),
		key:  filepath.Join(dir, "key.pem"),
		logs: &syncBuffer{},
		sig:  make(chan os.Signal, 1),
	}
	WriteTestCertPair(t, f.cert, f.key, "loaded", time.Now().Add(time.Hour))
	f.s = newGuardServer(t, &config.Config{TLSCert: f.cert, TLSKey: f.key, LogDir: t.TempDir()}, f.addr)
	f.s.logger = slog.New(slog.NewTextHandler(f.logs, &slog.HandlerOptions{Level: slog.LevelInfo}))
	f.s.certPollEvery = poll
	f.s.SetReloadSignals(f.sig)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.s.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Error("Start did not return within 30s of cancellation")
		}
	})
	waitFor(t, func() bool { return ServedCommonName(f.addr) == "loaded" })
	return f
}

// reload sends one SIGHUP and waits for the whole reload it starts to finish,
// so an assertion that the old certificate is still served is not reading a
// swap that has yet to happen.
func (f *certFixture) reload(t *testing.T) {
	t.Helper()
	f.reloadsLogged++
	f.sig <- syscall.SIGHUP
	waitFor(t, func() bool { return strings.Count(f.logs.String(), "reload complete") >= f.reloadsLogged })
}

// TestReloadKeepsTheLoadedCertificateWhenThePairIsBad walks the four ways a
// renewed pair can be unusable. Each must leave the loaded certificate in
// service, name the file and the reason at ERROR, and let the rest of the
// reload finish, which fixture.reload waits on.
func TestReloadKeepsTheLoadedCertificateWhenThePairIsBad(t *testing.T) {
	cases := []struct {
		name string
		// breakPair damages the pair on disk and returns the file the log
		// must name and a fragment of the reason.
		breakPair func(t *testing.T, f *certFixture) (file, reason string)
	}{
		{"unreadable", func(t *testing.T, f *certFixture) (string, string) {
			// A directory is unreadable to every user. A mode would not be:
			// root reads through 0000, and CI containers run as root.
			if err := os.Remove(f.cert); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(f.cert, 0o700); err != nil {
				t.Fatal(err)
			}
			return f.cert, "is a directory"
		}},
		{"unparseable", func(t *testing.T, f *certFixture) (string, string) {
			if err := os.WriteFile(f.cert, []byte("not a certificate\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			return f.cert, "no PEM certificate found"
		}},
		{"key does not match", func(t *testing.T, f *certFixture) (string, string) {
			other := filepath.Join(t.TempDir(), "other.pem")
			WriteTestCertPair(t, other, f.key, "other", time.Now().Add(time.Hour))
			return f.key, "private key does not match public key"
		}},
		{"expired", func(t *testing.T, f *certFixture) (string, string) {
			WriteTestCertPair(t, f.cert, f.key, "expired", time.Now().Add(-time.Hour))
			return f.cert, "certificate expired at"
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := startCertServer(t, 0)
			file, reason := tc.breakPair(t, f)
			f.reload(t)

			if got := ServedCommonName(f.addr); got != "loaded" {
				t.Errorf("after a reload of a bad pair the server presents %q, want the loaded certificate", got)
			}
			var line string
			for l := range strings.SplitSeq(f.logs.String(), "\n") {
				if strings.Contains(l, "level=ERROR") && strings.Contains(l, "TLS certificate not reloaded") {
					line = l
				}
			}
			if line == "" {
				t.Fatalf("no ERROR line for the refused pair:\n%s", f.logs.String())
			}
			if !strings.Contains(line, "file="+file+" ") || !strings.Contains(line, reason) {
				t.Errorf("ERROR line does not name file %s and reason %q:\n%s", file, reason, line)
			}

			// The refusal is not sticky: a good pair on the next reload is served.
			if err := os.RemoveAll(f.cert); err != nil {
				t.Fatal(err)
			}
			WriteTestCertPair(t, f.cert, f.key, "repaired", time.Now().Add(time.Hour))
			f.reload(t)
			if got := ServedCommonName(f.addr); got != "repaired" {
				t.Errorf("after repairing the pair the server presents %q, want %q", got, "repaired")
			}
		})
	}
}

// TestChangedCertificateFilesReloadWithoutASignal replaces the pair and sends
// nothing. The poll has to notice the modification times, swap, and log the
// certificate it installed; before the replacement it has to reload nothing,
// or every tick would reread a pair nobody touched.
func TestChangedCertificateFilesReloadWithoutASignal(t *testing.T) {
	if certPollInterval < time.Minute {
		t.Fatalf("certPollInterval is %s; the files are to be checked at most once a minute", certPollInterval)
	}
	const tick = 20 * time.Millisecond
	f := startCertServer(t, tick)

	time.Sleep(10 * tick)
	if logs := f.logs.String(); strings.Contains(logs, "TLS certificate loaded") {
		t.Fatalf("the poll reloaded a pair whose files did not change:\n%s", logs)
	}

	expires := time.Now().Add(48 * time.Hour)
	WriteTestCertPair(t, f.cert, f.key, "renewed", expires)
	// A filesystem with coarse timestamps can stamp the rewrite with the time
	// the first write got.
	stamp := time.Now().Add(5 * time.Second)
	for _, p := range []string{f.cert, f.key} {
		if err := os.Chtimes(p, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, func() bool { return ServedCommonName(f.addr) == "renewed" })

	var line string
	waitFor(t, func() bool {
		for l := range strings.SplitSeq(f.logs.String(), "\n") {
			if strings.Contains(l, "level=INFO") && strings.Contains(l, "TLS certificate loaded") {
				line = l
			}
		}
		return line != ""
	})
	for _, want := range []string{
		`subject="CN=renewed"`,
		`issuer="CN=renewed"`,
		"expires=" + expires.UTC().Format(time.RFC3339),
	} {
		if !strings.Contains(line, want) {
			t.Errorf("INFO line lacks %q:\n%s", want, line)
		}
	}
	if strings.Contains(f.logs.String(), "reload requested") {
		t.Errorf("a signal reload ran; this test sends none:\n%s", f.logs.String())
	}
}
