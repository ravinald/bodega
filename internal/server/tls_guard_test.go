package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ravinald/bodega/internal/config"
	"github.com/ravinald/bodega/internal/logging"
	"github.com/ravinald/bodega/internal/manifest"
)

// TestStartTLSMatrix drives Start through every combination of tls_cert and
// tls_key and asserts which bind, which refuse, and which scheme the ones that
// bind actually answer on.
//
// The scheme assertion is the point. Before allow_plaintext, an empty pair
// bound plain HTTP on whatever listen_addr named and nothing in the process
// disagreed: the banner said http:// and was correct, which is why the defect
// survived a reading of the code.
func TestStartTLSMatrix(t *testing.T) {
	certPath, keyPath := writeCertPair(t)

	for _, tc := range []struct {
		name       string
		cert, key  string
		allowPlain bool
		wantScheme string // "" means Start must refuse
		wantErr    string
	}{
		{name: "both set", cert: certPath, key: keyPath, wantScheme: "https"},
		{name: "cert alone", cert: certPath, wantErr: "tls_key is empty"},
		{name: "key alone", key: keyPath, wantErr: "tls_cert is empty"},
		{name: "neither", wantErr: "refusing to serve plaintext HTTP"},
		{name: "neither, plaintext authorized", allowPlain: true, wantScheme: "http"},
		{name: "both set, plaintext authorized", cert: certPath, key: keyPath, allowPlain: true, wantScheme: "https"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := reservePort(t)
			s := newGuardServer(t, &config.Config{
				TLSCert:        tc.cert,
				TLSKey:         tc.key,
				AllowPlaintext: tc.allowPlain,
				LogDir:         t.TempDir(),
			}, addr)

			if tc.wantScheme == "" {
				err := s.Start(context.Background())
				if err == nil {
					t.Fatal("Start bound a listener it should have refused")
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %q does not name %q", err, tc.wantErr)
				}
				assertNothingListening(t, addr)
				return
			}

			scheme := startAndProbe(t, s, addr)
			if scheme != tc.wantScheme {
				t.Errorf("listener answered %s, want %s", scheme, tc.wantScheme)
			}
		})
	}
}

// TestStartRefusesPlaintextOn443 covers the evidence a port carries. 443 is
// not authorization, but an operator who wrote it expected TLS, so an empty
// cert pair there refuses with the port named rather than binding in the clear
// where every client will assume a handshake.
func TestStartRefusesPlaintextOn443(t *testing.T) {
	// :443 is privileged, so this never reaches a bind — the guard runs first
	// and that is what the test asserts.
	s := newGuardServer(t, &config.Config{LogDir: t.TempDir()}, "0.0.0.0:443")
	err := s.Start(context.Background())
	if err == nil {
		t.Fatal("Start accepted plaintext on 443")
	}
	for _, want := range []string{"443", "expecting TLS", "allow_plaintext"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
}

// TestPlaintextOn443AtDefaultLogLevel drives Start on the port every client
// reads as TLS, with plaintext authorized, and asserts the hazard reaches an
// operator running the shipped log_level.
//
// The level is the whole test. The line was a Warn and logging.SlogLevel(0) is
// slog.LevelError, so on a default install it printed nothing while USAGE.md
// said it fired on every start (#131). Raising the verbosity in the test is
// what let that survive, so the handler here is the real one at the real
// default rather than a permissive one.
func TestPlaintextOn443AtDefaultLogLevel(t *testing.T) {
	var buf syncBuffer
	s := newGuardServer(t, &config.Config{AllowPlaintext: true, LogDir: t.TempDir()}, "127.0.0.1:443")
	s.logger = slog.New(logging.NewHandler(&buf, logging.SlogLevel(0)))

	// Run rather than probe: :443 is privileged, so an unprivileged run fails
	// at net.Listen and a run as root (CI's container) binds and serves. The
	// guard logs before either, so both reach the assertion.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Error("server did not shut down")
		}
	})

	waitFor(t, func() bool { return strings.Contains(buf.String(), "in the clear") })
	out := buf.String()
	for _, want := range []string{"ERROR", "in the clear", "allow_plaintext", "127.0.0.1:443"} {
		if !strings.Contains(out, want) {
			t.Errorf("log at the default level does not name %q:\n%s", want, out)
		}
	}
}

// TestPlaintextOffTLSPortIsSilent keeps the rule from degrading into "log
// everything at Error". A loopback listener behind a proxy that terminates TLS
// is the documented deployment, and what it serves is what the operator asked
// for, so it earns no startup line at all.
func TestPlaintextOffTLSPortIsSilent(t *testing.T) {
	var buf syncBuffer
	addr := reservePort(t)
	s := newGuardServer(t, &config.Config{AllowPlaintext: true, LogDir: t.TempDir()}, addr)
	s.logger = slog.New(logging.NewHandler(&buf, logging.SlogLevel(0)))

	if err := s.guardPlaintext(); err != nil {
		t.Fatalf("guardPlaintext refused an authorized plaintext listener: %v", err)
	}
	if got := buf.String(); got != "" {
		t.Errorf("authorized plaintext off :443 logged at the default level:\n%s", got)
	}
}

// TestStorage503NamesNoDriver pins the body every package route answers when
// no backend could be built. It named S3 on installs whose config never
// mentioned one, which sent operators looking for a bucket that did not exist
// (#34); the handler cannot know the driver, so it points at the startup log,
// which startupStorage writes at Error.
func TestStorage503NamesNoDriver(t *testing.T) {
	s := newGuardServer(t, &config.Config{AllowPlaintext: true, LogDir: t.TempDir()}, reservePort(t))
	for _, path := range []string{"/pypi/simple/", "/binaries/x/y", "/git/x/y.bundle"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s answered %d, want 503", path, rec.Code)
		}
		body := rec.Body.String()
		if strings.Contains(strings.ToLower(body), "s3") {
			t.Errorf("%s names a driver the config may never have asked for: %q", path, body)
		}
		if !strings.Contains(body, "startup log") {
			t.Errorf("%s does not point at where the reason is: %q", path, body)
		}
	}
}

// syncBuffer is a bytes.Buffer a slog handler on one goroutine can write while
// the test reads it on another.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func newGuardServer(t *testing.T, cfg *config.Config, addr string) *Server {
	t.Helper()
	cfg.AuditDB = filepath.Join(t.TempDir(), "audit.db")
	s := newServer(cfg, manifest.NewLocalStore(t.TempDir()), nil, addr,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.SetQuiet(true)
	if s.auditDB != nil {
		t.Cleanup(func() { _ = s.auditDB.Close() })
	}
	return s
}

// startAndProbe runs Start, waits for the port to answer, and reports the
// scheme the listener spoke: "https" if /healthz answers 200 over a TLS
// handshake, "http" if it answers 200 in the clear.
func startAndProbe(t *testing.T, s *Server, addr string) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Start returned %v", err)
			}
		case <-time.After(30 * time.Second):
			t.Error("server did not shut down")
		}
	})

	// Probed by scheme rather than by a bare TCP dial: a connect that opens
	// and closes without a ClientHello is a handshake error on a TLS listener,
	// which buries the real failure under log noise on every run.
	//
	// Neither arm answering means the listener is not up yet, so waitFor
	// retries. Start binds a few statements after the goroutine begins, and
	// the first iteration can land in that window.
	var scheme string
	waitFor(t, func() bool {
		switch {
		case probeTLS(addr):
			scheme = "https"
		case probePlain(addr):
			scheme = "http"
		}
		return scheme != ""
	})
	return scheme
}

// Both probes require a 200 rather than any response at all. A TLS listener
// answers a plaintext request with a plaintext "400 Bad Request: client sent
// an HTTP request to an HTTPS server", so a returned status line is evidence
// that something is on the port, not evidence of which scheme it speaks.
// /healthz is an unconditional 200 that reaches neither storage nor the admin
// gate, which makes it the one route whose status carries no other meaning.
func probeTLS(addr string) bool {
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // self-signed fixture
	}
	resp, err := client.Get("https://" + addr + "/healthz")
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func probePlain(addr string) bool {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + addr + "/healthz")
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func assertNothingListening(t *testing.T, addr string) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
	if err == nil {
		_ = c.Close()
		t.Errorf("something is listening on %s after Start refused", addr)
	}
}

// reservePort binds an ephemeral port, reads it back and releases it. Start
// takes an address rather than returning the one it bound, and the probe needs
// a port to aim at.
func reservePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved port: %v", err)
	}
	return addr
}

// writeCertPair writes a self-signed leaf for 127.0.0.1 and returns the two
// paths. TLS 1.3 is the configured floor, so the key has to be one 1.3 will
// negotiate; P-256 is.
func writeCertPair(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "bodega-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	write := func(path, blockType string, der []byte) {
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	write(certPath, "CERTIFICATE", der)
	write(keyPath, "EC PRIVATE KEY", keyDER)
	return certPath, keyPath
}
