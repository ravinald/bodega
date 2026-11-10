package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// certPollInterval bounds how often the certificate files are statted. A
// renewer that runs no deploy hook is noticed within this long.
const certPollInterval = time.Minute

// certReloader holds the certificate the TLS listener serves and replaces it
// from disk. Handshakes read it through GetCertificate, so a swap reaches the
// next handshake and never touches a connection that already completed one.
type certReloader struct {
	certFile, keyFile string
	logger            *slog.Logger
	now               func() time.Time

	current atomic.Pointer[tls.Certificate]

	// mu orders reloads, so a SIGHUP and a poll arriving together cannot
	// install the older of two reads last.
	mu                sync.Mutex
	certMod, keyMod   time.Time
	certSeen, keySeen bool
}

// certLoadError names the file a failed load is attributed to.
type certLoadError struct {
	file string
	err  error
}

func (e *certLoadError) Error() string { return e.file + ": " + e.err.Error() }
func (e *certLoadError) Unwrap() error { return e.err }

// newCertReloader loads the pair once and fails when it cannot, which keeps a
// misconfigured server from binding. Expiry is not judged here: a server that
// restarts under an expired certificate serves it, as it always has, and the
// client's handshake error says why.
func newCertReloader(certFile, keyFile string, logger *slog.Logger) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile, logger: logger, now: time.Now}
	r.recordModTimes()
	cert, err := loadCertPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	r.current.Store(cert)
	return r, nil
}

// GetCertificate is tls.Config.GetCertificate.
func (r *certReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.current.Load(), nil
}

// reload rereads both files and installs the pair, or keeps the loaded one
// and logs why. A pair is refused when it cannot be read or parsed, when the
// key does not match, and when the certificate has already expired: swapping
// in any of those turns a server that is answering into one that is not.
func (r *certReloader) reload() {
	r.mu.Lock()
	defer r.mu.Unlock()
	// Read before the load, so a file written while the load runs differs
	// from what was recorded and the next poll picks it up.
	r.recordModTimes()

	cert, err := loadCertPair(r.certFile, r.keyFile)
	if err == nil && r.now().After(cert.Leaf.NotAfter) {
		err = &certLoadError{file: r.certFile, err: fmt.Errorf("certificate expired at %s", cert.Leaf.NotAfter.UTC().Format(time.RFC3339))}
	}
	if err != nil {
		file := r.certFile
		var le *certLoadError
		if errors.As(err, &le) {
			file, err = le.file, le.err
		}
		r.logger.Error("TLS certificate not reloaded; the loaded certificate stays in service",
			"file", file, "error", err, "tls_cert", r.certFile, "tls_key", r.keyFile)
		return
	}
	r.current.Store(cert)
	r.logger.Info("TLS certificate loaded",
		"subject", cert.Leaf.Subject.String(),
		"issuer", cert.Leaf.Issuer.String(),
		"expires", cert.Leaf.NotAfter.UTC().Format(time.RFC3339))
}

// recordModTimes stores what the two files report now. A file that cannot be
// statted records as unseen, so its return counts as a change.
func (r *certReloader) recordModTimes() {
	r.certMod, r.certSeen = modTime(r.certFile)
	r.keyMod, r.keySeen = modTime(r.keyFile)
}

func (r *certReloader) changed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	certMod, certSeen := modTime(r.certFile)
	keyMod, keySeen := modTime(r.keyFile)
	return certSeen != r.certSeen || keySeen != r.keySeen ||
		!certMod.Equal(r.certMod) || !keyMod.Equal(r.keyMod)
}

// poll reloads when either file's modification time moved, until ctx ends.
// The times are recorded on every attempt, failed ones included, so a bad
// file is reported once rather than at every tick, and fixing it is itself a
// change.
func (r *certReloader) poll(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if r.changed() {
				r.reload()
			}
		}
	}
}

// modTime follows symlinks, which is what makes certbot's live/ directory
// work: renewal repoints the link and the target's time is the one that moves.
func modTime(path string) (time.Time, bool) {
	fi, err := os.Stat(path)
	if err != nil {
		return time.Time{}, false
	}
	return fi.ModTime(), true
}

// loadCertPair reads and pairs the two files. Every certificate in the file
// is parsed first, for two reasons. tls.X509KeyPair parses only the leaf and
// carries the rest of the chain as opaque bytes, so a damaged intermediate
// would be installed and then refused by every client. And once the whole
// chain parses, whatever tls.X509KeyPair refuses is the key, unparseable or
// not matching, which is how a failure gets attributed to a file.
func loadCertPair(certFile, keyFile string) (*tls.Certificate, error) {
	certPEM, err := os.ReadFile(certFile) //nolint:gosec // operator-configured path
	if err != nil {
		return nil, &certLoadError{file: certFile, err: err}
	}
	keyPEM, err := os.ReadFile(keyFile) //nolint:gosec // operator-configured path
	if err != nil {
		return nil, &certLoadError{file: keyFile, err: err}
	}
	if err := parseChain(certPEM); err != nil {
		return nil, &certLoadError{file: certFile, err: err}
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, &certLoadError{file: keyFile, err: err}
	}
	return &cert, nil
}

// parseChain parses each CERTIFICATE block, the set tls.X509KeyPair sends to
// clients. It checks syntax only: whether the chain leads to a root is the
// client's judgment.
func parseChain(certPEM []byte) error {
	n := 0
	for {
		var block *pem.Block
		block, certPEM = pem.Decode(certPEM)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		n++
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return fmt.Errorf("certificate %d in the file: %w", n, err)
		}
	}
	if n == 0 {
		return errors.New("no PEM certificate found")
	}
	return nil
}
