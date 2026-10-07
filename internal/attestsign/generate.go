package attestsign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Generate creates one new key. The server never calls this: key material is
// created by an operator running the CLI and delivered to the service
// read-only, so a compromised server process cannot mint a key verifiers
// would then be asked to trust.
func Generate() (*KeyRing, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate an ed25519 key: %w", err)
	}
	k, err := newKey(pub, priv)
	if err != nil {
		return nil, err
	}
	k.created = time.Now().UTC().Truncate(time.Second)
	return &KeyRing{keys: []*Key{k}}, nil
}

// Add appends other's keys. The last one appended becomes the signer, and
// every key already in the ring stays published.
func (k *KeyRing) Add(other *KeyRing) {
	k.keys = append(k.keys, other.keys...)
}

// MinRetirePrefix is the shortest key ID prefix Retire accepts. Retiring the
// wrong key erases a secret nothing can restore, so the identifier has to be
// one an operator cannot reach by typing part of something else.
const MinRetirePrefix = 16

// Retire erases the private half of the key whose ID starts with id and
// reports the full ID. The public half stays in the file and stays published,
// because attestations it already signed still need verifying.
//
// It refuses a prefix shorter than MinRetirePrefix, a prefix matching more
// than one key, a key already retired, and the last key that can sign: a
// file with no signing key loads as an error, and the server would keep the
// retired key signing until a restart.
func (k *KeyRing) Retire(id string) (string, error) {
	want := strings.ToLower(strings.Join(strings.Fields(id), ""))
	if len(want) < MinRetirePrefix {
		return "", fmt.Errorf("%q is shorter than the %d characters retire requires; pass the full 64-character key ID or a prefix of at least %d (have: %s)",
			id, MinRetirePrefix, MinRetirePrefix, strings.Join(k.ids(), ", "))
	}
	var matched []*Key
	for _, key := range k.keys {
		if strings.HasPrefix(key.id, want) {
			matched = append(matched, key)
		}
	}
	switch len(matched) {
	case 0:
		return "", fmt.Errorf("no key whose ID starts with %q in %s (have: %s)", want, k.path, strings.Join(k.ids(), ", "))
	case 1:
	default:
		return "", fmt.Errorf("%q matches %d keys in %s; pass the full key ID", want, len(matched), k.path)
	}
	target := matched[0]
	if target.priv == nil {
		return "", fmt.Errorf("key %s in %s is already retired", target.id, k.path)
	}
	if k.activeCount() == 1 {
		return "", fmt.Errorf("refusing to retire the only signing key in %s; run `bodega attest key generate --force` to add its replacement first", k.path)
	}
	target.priv = nil
	target.retired = time.Now().UTC().Truncate(time.Second)
	return target.id, nil
}

func (k *KeyRing) activeCount() int {
	n := 0
	for _, key := range k.keys {
		if key.priv != nil {
			n++
		}
	}
	return n
}

func (k *KeyRing) ids() []string {
	out := make([]string, 0, len(k.keys))
	for _, key := range k.keys {
		out = append(out, key.id)
	}
	return out
}

// WritePrivate writes every key to path, mode 0600, replacing the file
// atomically so a reader never sees half a key. A signing key is written as
// PKCS#8 and a retired one as its public half alone, each below the metadata
// lines readMeta parses.
func (k *KeyRing) WritePrivate(path string) error {
	var buf bytes.Buffer
	for _, key := range k.keys {
		if !key.created.IsZero() {
			fmt.Fprintf(&buf, "%s %s\n", metaCreated, key.created.Format(time.RFC3339))
		}
		block := &pem.Block{}
		if key.priv != nil {
			der, err := x509.MarshalPKCS8PrivateKey(key.priv)
			if err != nil {
				return fmt.Errorf("serialize key %s: %w", key.id, err)
			}
			block.Type, block.Bytes = "PRIVATE KEY", der
		} else {
			if !key.retired.IsZero() {
				fmt.Fprintf(&buf, "%s %s\n", metaRetired, key.retired.Format(time.RFC3339))
			}
			der, err := x509.MarshalPKIXPublicKey(key.pub)
			if err != nil {
				return fmt.Errorf("serialize key %s: %w", key.id, err)
			}
			block.Type, block.Bytes = "PUBLIC KEY", der
		}
		if err := pem.Encode(&buf, block); err != nil {
			return fmt.Errorf("encode key %s: %w", key.id, err)
		}
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".attest-signing-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp key in %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp key %s: %w", tmpName, err)
	}
	if _, err := tmp.Write(buf.Bytes()); err != nil {
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
// generation lands where the server searches.
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
