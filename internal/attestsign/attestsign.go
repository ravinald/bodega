// Package attestsign holds the key bodega signs attestations with: statements
// about what it admitted, and nothing else.
//
// It is a third key rather than a reuse of the apt or pkg one because a key
// that signs two kinds of statement lets a theft of one forge the other. A
// stolen attestation key must not be able to sign an InRelease, and a stolen
// apt key must not be able to vouch for a dependency.
//
// The loading rules are internal/pkgsign's: the same search order, the same
// refusal of a key readable beyond its owner, and a key the operator creates
// with the CLI and the server only ever loads. The file differs in one way. It
// may hold several keys, because an attestation outlives the rotation that
// retires its key: a verifier holding last month's attestation still needs
// last month's public key, so retiring a key erases its secret half and keeps
// its public half published.
package attestsign

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Signer is what an attestation producer needs: a crypto.Signer over the raw
// message bytes, and the identifier a verifier pins. A KMS-backed signer
// satisfies it without touching a caller.
type Signer interface {
	crypto.Signer
	// KeyID is the lowercase hex SHA-256 of the DER SubjectPublicKeyInfo.
	KeyID() string
}

// Algorithm is the only key type this package loads or generates.
const Algorithm = "ed25519"

// KeyFileName is the basename the key carries in every search location.
const KeyFileName = "attest-signing.key"

// SystemKeyPath is the packaged location for a key not delivered as a systemd
// credential. A var so a test can determine the whole search order; nothing
// outside a test assigns it.
var SystemKeyPath = "/etc/bodega/" + KeyFileName

// CredentialsEnv is the directory systemd's LoadCredential= populates.
const CredentialsEnv = "CREDENTIALS_DIRECTORY"

// ErrNoKey reports that no key exists at any searched path. Serving without
// one is supported; the server tells this apart from a key that is present
// and unusable.
var ErrNoKey = errors.New("no attestation signing key found")

// Metadata lines written above each PEM block. RFC 7468 lets explanatory text
// precede a block and requires parsers to skip it, so openssl still reads the
// file; PEM headers inside the block would have made it unreadable to openssl,
// which accepts no header on a PKCS#8 body but Proc-Type.
const (
	metaCreated = "Created:"
	metaRetired = "Retired:"
)

// Key is one attestation key. A retired key has no private half and cannot
// sign; it stays in the file so its public half stays published.
type Key struct {
	id      string
	pub     ed25519.PublicKey
	priv    ed25519.PrivateKey
	created time.Time
	retired time.Time
}

// KeyID is the lowercase hex SHA-256 of the DER SubjectPublicKeyInfo.
func (k *Key) KeyID() string { return k.id }

// Public returns the ed25519.PublicKey.
func (k *Key) Public() crypto.PublicKey { return k.pub }

// Sign signs msg itself, with no digest of its own in front. The DSSE
// pre-authentication encoding is the caller's to build, and a second hash
// here would produce a signature no Ed25519 verifier given the same message
// accepts. Ed25519ph and Ed25519ctx are refused rather than honored, so a
// caller cannot get a variant a verifier is not expecting.
func (k *Key) Sign(_ io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	if k.priv == nil {
		return nil, fmt.Errorf("attestation key %s is retired and holds no private key", k.id)
	}
	if opts != nil && opts.HashFunc() != crypto.Hash(0) {
		return nil, fmt.Errorf("attestation key %s signs raw message bytes; pass crypto.Hash(0), not %v", k.id, opts.HashFunc())
	}
	if o, ok := opts.(*ed25519.Options); ok && o.Context != "" {
		return nil, fmt.Errorf("attestation key %s signs plain Ed25519; a context string is not supported", k.id)
	}
	return ed25519.Sign(k.priv, msg), nil
}

// KeyInfo describes one key as the server publishes it and the CLI shows it.
type KeyInfo struct {
	KeyID        string
	Algorithm    string
	PublicKeyPEM []byte
	// Created is zero when the file carries no Created: line, which is the
	// case for a key made with openssl rather than the CLI.
	Created time.Time
	// Retired is zero while the key can sign.
	Retired time.Time
}

// KeyRing is every key in one file, in file order. The last key that is not
// retired signs.
type KeyRing struct {
	path string
	keys []*Key
}

// DefaultKeyPaths is the search order: the systemd credential first, then the
// packaged system path, then a file beside the artifacts. storagePath may be
// empty, which drops the last entry.
func DefaultKeyPaths(storagePath string) []string {
	var paths []string
	if dir := os.Getenv(CredentialsEnv); dir != "" {
		paths = append(paths, filepath.Join(dir, KeyFileName))
	}
	paths = append(paths, SystemKeyPath)
	if storagePath != "" {
		paths = append(paths, filepath.Join(storagePath, KeyFileName))
	}
	return paths
}

// WritablePaths is DefaultKeyPaths without the systemd credential directory,
// which is a read-only tmpfs.
func WritablePaths(storagePath string) []string {
	paths := []string{SystemKeyPath}
	if storagePath != "" {
		paths = append(paths, filepath.Join(storagePath, KeyFileName))
	}
	return paths
}

// inCredentialsDir reports whether path is inside this service's systemd
// credential directory. An unset, relative or root CREDENTIALS_DIRECTORY
// exempts nothing, for the reasons internal/pkgsign gives.
func inCredentialsDir(path string) bool {
	dir := os.Getenv(CredentialsEnv)
	if dir == "" || !filepath.IsAbs(dir) || filepath.Clean(dir) == string(filepath.Separator) {
		return false
	}
	return strings.HasPrefix(filepath.Clean(path), filepath.Clean(dir)+string(filepath.Separator))
}

// Load reads the first key file that exists, in the order given. A file that
// exists and cannot be used is an error rather than a skip, so a broken key
// never quietly hands signing to a different file further down the list.
func Load(paths []string) (*KeyRing, error) {
	for _, p := range paths {
		kr, err := LoadPath(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return kr, nil
	}
	return nil, fmt.Errorf("%w (searched: %s)", ErrNoKey, strings.Join(paths, ", "))
}

// LoadPath reads one key file. Every error but a missing file names path.
func LoadPath(path string) (*KeyRing, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	// Refused rather than warned about, with the group bit forgiven inside
	// $CREDENTIALS_DIRECTORY only, where systemd writes 0440 on a read-only
	// tmpfs. internal/pkgsign carries the full argument.
	mode := info.Mode().Perm()
	if mode&0o007 != 0 || (mode&0o070 != 0 && !inCredentialsDir(path)) {
		return nil, fmt.Errorf("attestation signing key %s is mode %#o and readable beyond its owner; run chmod 600 %s", path, mode, path)
	}
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied path from the documented search order
	if err != nil {
		return nil, fmt.Errorf("read attestation signing key %s: %w", path, err)
	}
	keys, err := parseKeys(data)
	if err != nil {
		return nil, fmt.Errorf("attestation signing key %s: %w", path, err)
	}
	kr := &KeyRing{path: path, keys: keys}
	if kr.active() == nil {
		return nil, fmt.Errorf("attestation signing key %s holds only retired keys, so nothing can sign; restore a signing key from backup or move the file aside and generate a new one", path)
	}
	return kr, nil
}

// parseKeys reads every PEM block in data with the metadata lines above it.
func parseKeys(data []byte) ([]*Key, error) {
	const begin = "-----BEGIN "
	var keys []*Key
	seen := map[string]bool{}
	rest := data
	for {
		i := bytes.Index(rest, []byte(begin))
		if i < 0 {
			break
		}
		preamble := rest[:i]
		block, next := pem.Decode(rest[i:])
		if block == nil {
			return nil, errors.New("a PEM block is malformed or unterminated")
		}
		rest = next
		k, err := parseBlock(block)
		if err != nil {
			return nil, err
		}
		if err := k.readMeta(preamble); err != nil {
			return nil, fmt.Errorf("key %s: %w", k.id, err)
		}
		if seen[k.id] {
			return nil, fmt.Errorf("key %s appears twice", k.id)
		}
		seen[k.id] = true
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return nil, errors.New("not PEM; create it with `bodega attest key generate` or `openssl genpkey -algorithm ed25519`")
	}
	return keys, nil
}

func parseBlock(block *pem.Block) (*Key, error) {
	switch block.Type {
	case "PRIVATE KEY":
		if len(block.Headers) > 0 {
			return nil, errors.New("a PRIVATE KEY block carries PEM headers; bodega reads an unencrypted PKCS#8 body only")
		}
		raw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse the PKCS#8 body: %w", err)
		}
		priv, ok := raw.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("a %T, where attestation keys are Ed25519", raw)
		}
		return newKey(priv.Public().(ed25519.PublicKey), priv)
	case "PUBLIC KEY":
		raw, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse a retired public key: %w", err)
		}
		pub, ok := raw.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("a retired key is a %T; attestation keys are Ed25519", raw)
		}
		return newKey(pub, nil)
	case "ENCRYPTED PRIVATE KEY":
		return nil, errors.New("passphrase-protected; bodega runs unattended and cannot prompt — export it without a passphrase and protect it with file permissions instead")
	}
	return nil, fmt.Errorf("a %q block, where attestation keys are PKCS#8 PRIVATE KEY", block.Type)
}

func newKey(pub ed25519.PublicKey, priv ed25519.PrivateKey) (*Key, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("render the public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return &Key{id: hex.EncodeToString(sum[:]), pub: pub, priv: priv}, nil
}

// readMeta takes Created: and Retired: from the text above a block. Any other
// line is explanatory text and ignored. A public-only block is retired
// whether or not it says when.
func (k *Key) readMeta(preamble []byte) error {
	for _, line := range strings.Split(string(preamble), "\n") {
		line = strings.TrimSpace(line)
		for prefix, dst := range map[string]*time.Time{metaCreated: &k.created, metaRetired: &k.retired} {
			v, ok := strings.CutPrefix(line, prefix)
			if !ok {
				continue
			}
			t, err := time.Parse(time.RFC3339, strings.TrimSpace(v))
			if err != nil {
				return fmt.Errorf("%s line %q is not RFC 3339", strings.TrimSuffix(prefix, ":"), line)
			}
			*dst = t.UTC()
		}
	}
	if k.priv != nil && !k.retired.IsZero() {
		return errors.New("marked retired but still carries its private key; run `bodega attest key retire` rather than editing the file")
	}
	return nil
}

// Path reports the file this ring was read from or last written to.
func (k *KeyRing) Path() string { return k.path }

// Len reports how many keys the file holds, retired ones included.
func (k *KeyRing) Len() int { return len(k.keys) }

// active is the last key that can sign.
func (k *KeyRing) active() *Key {
	for i := len(k.keys) - 1; i >= 0; i-- {
		if k.keys[i].priv != nil {
			return k.keys[i]
		}
	}
	return nil
}

// Signer returns the newest key that is not retired. A ring from Load or
// Generate always has one.
func (k *KeyRing) Signer() Signer {
	if a := k.active(); a != nil {
		return a
	}
	return nil
}

// Keys describes every key in file order: the published set.
func (k *KeyRing) Keys() []KeyInfo {
	out := make([]KeyInfo, 0, len(k.keys))
	for _, key := range k.keys {
		der, err := x509.MarshalPKIXPublicKey(key.pub)
		if err != nil {
			// newKey already marshaled this exact key to compute its ID.
			continue
		}
		out = append(out, KeyInfo{
			KeyID:        key.id,
			Algorithm:    Algorithm,
			PublicKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}),
			Created:      key.created,
			Retired:      key.retired,
		})
	}
	return out
}
