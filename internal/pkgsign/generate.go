package pkgsign

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// rsaBits is the modulus size Generate produces. pkg's own repositories sign
// with 2048; 4096 costs a few milliseconds per rebuild on a document that is
// rebuilt when its object set changes, and nothing on the client side notices
// the difference.
const rsaBits = 4096

// Generate creates one new signing key. The server never calls this: key
// material is created by an operator running the CLI and delivered to the
// service read-only, so a compromised server process cannot mint a key that
// clients would then be asked to trust.
func Generate(kt KeyType) (*KeyRing, error) {
	switch kt {
	case KeyRSA, "":
		key, err := rsa.GenerateKey(rand.Reader, rsaBits)
		if err != nil {
			return nil, fmt.Errorf("generate an rsa-%d key: %w", rsaBits, err)
		}
		return newKeyRing(key)
	case KeyEd25519:
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate an eddsa key: %w", err)
		}
		return newKeyRing(key)
	}
	return nil, fmt.Errorf("unknown key type %q (want %q or %q)", kt, KeyRSA, KeyEd25519)
}

// WritePrivate writes the secret half to path as a PKCS#8 PEM block, mode
// 0600, replacing the file atomically so a reader never sees a half-written
// key.
func (k *KeyRing) WritePrivate(path string) error {
	der, err := x509.MarshalPKCS8PrivateKey(k.key)
	if err != nil {
		return fmt.Errorf("serialize the secret key: %w", err)
	}
	body := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".pkg-signing-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp key in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp key %s: %w", tmpName, err)
	}
	if _, err := tmp.Write(body); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp key %s: %w", tmpName, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp key %s: %w", tmpName, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("install key at %s: %w", path, err)
	}
	k.path = path
	return nil
}

// FirstWritablePath returns the first path whose directory can be created, so
// key generation lands where the server searches rather than wherever the
// operator happened to be standing.
func FirstWritablePath(paths []string) (string, error) {
	var last error
	for _, p := range paths {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			last = err
			continue
		}
		return p, nil
	}
	if last == nil {
		last = fmt.Errorf("no candidate paths")
	}
	return "", fmt.Errorf("no writable key path (tried: %s): %w", strings.Join(paths, ", "), last)
}

// TrustedFingerprintFile is the file a client installs under
// /usr/local/etc/pkg/fingerprints/<repo>/trusted/, rendered from this key.
//
// It is emitted rather than described because the format is two keys in UCL
// and every operator who types it by hand types "function" as "hash" once. A
// client that has this file verifies the .pub member inside the archive
// against it and then checks the signature with that key, which is how
// signature_type: FINGERPRINTS works upstream.
func (k *KeyRing) TrustedFingerprintFile() string {
	return fmt.Sprintf("function: \"sha256\"\nfingerprint: \"%s\"\n", k.Fingerprint())
}
