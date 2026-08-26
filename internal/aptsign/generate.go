package aptsign

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// KeyType names a generation algorithm.
type KeyType string

const (
	// KeyEd25519 is the default: small, fast, and understood by gnupg 2.1
	// and later, which covers every apt release still receiving updates.
	KeyEd25519 KeyType = "ed25519"
	// KeyRSA4096 exists for clients whose gnupg predates 2.1 and cannot
	// parse an EdDSA key at all — it fails at import, not at verify.
	KeyRSA4096 KeyType = "rsa4096"
)

// Generate creates one new signing key. The server never calls this: key
// material is created by an operator running the CLI and delivered to the
// service read-only, so a compromised server process cannot mint a key that
// clients would then be asked to trust.
func Generate(name, email string, kt KeyType) (*KeyRing, error) {
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("key name is empty; set apt_signing_name in config.json or pass --name")
	}
	cfg := &packet.Config{DefaultHash: hashAlgo}
	switch kt {
	case KeyEd25519, "":
		cfg.Algorithm = packet.PubKeyAlgoEdDSA
	case KeyRSA4096:
		cfg.Algorithm = packet.PubKeyAlgoRSA
		cfg.RSABits = 4096
	default:
		return nil, fmt.Errorf("unknown key type %q (want %q or %q)", kt, KeyEd25519, KeyRSA4096)
	}
	// No UID comment: gpg renders it inline and apt shows the whole UID in
	// its warnings, where "name (comment) <email>" is just noise.
	e, err := openpgp.NewEntity(name, "", email, cfg)
	if err != nil {
		return nil, fmt.Errorf("generate %s key: %w", kt, err)
	}
	return &KeyRing{entities: openpgp.EntityList{e}}, nil
}

// Add appends other's keys, which is how a rotation window opens: the incoming
// key joins the outgoing one and both sign until clients have the new
// fingerprint.
func (k *KeyRing) Add(other *KeyRing) {
	k.entities = append(k.entities, other.entities...)
}

// Retire drops the key with the given fingerprint, closing a rotation window.
// It refuses to remove the last key, because a key file with no keys is
// indistinguishable at load from a corrupt one and takes the repository
// unsigned without saying so.
func (k *KeyRing) Retire(fp string) error {
	want := strings.ToUpper(strings.ReplaceAll(fp, " ", ""))
	if want == "" {
		return fmt.Errorf("no fingerprint given")
	}
	var kept openpgp.EntityList
	found := false
	for _, e := range k.entities {
		if strings.HasSuffix(fingerprint(e), want) {
			found = true
			continue
		}
		kept = append(kept, e)
	}
	if !found {
		return fmt.Errorf("no key matching %q in %s (have: %s)", fp, k.path, strings.Join(k.Fingerprints(), ", "))
	}
	if len(kept) == 0 {
		return fmt.Errorf("refusing to retire the only key in %s; generate the replacement with --rotate first, then retire this one", k.path)
	}
	k.entities = kept
	return nil
}

// WritePrivate writes every key's secret half to path as concatenated armored
// blocks, mode 0600, replacing the file atomically so a reader never sees a
// half-written key.
func (k *KeyRing) WritePrivate(path string) error {
	var buf bytes.Buffer
	for _, e := range k.entities {
		var raw bytes.Buffer
		if err := e.SerializePrivateWithoutSigning(&raw, nil); err != nil {
			return fmt.Errorf("serialize secret key %s: %w", fingerprint(e), err)
		}
		block, err := armorBytes(openpgp.PrivateKeyType, raw.Bytes())
		if err != nil {
			return err
		}
		buf.Write(block)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, ".apt-signing-*.tmp")
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

// FirstWritablePath returns the first path whose directory can be created,
// so key generation lands where the server searches rather than wherever the
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
