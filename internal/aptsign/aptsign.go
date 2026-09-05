// Package aptsign signs the generated apt index with OpenPGP.
//
// What a signature here proves is narrow and worth stating once: it seals the
// last hop. A client that verifies it knows the bytes are the ones bodega
// asserted, and nothing else. It carries no claim about upstream — the build
// host does verify an `apt-get download` against the distro's own keyring, but
// that result is recorded nowhere, and a source-built .deb never had an
// upstream signature to begin with. For mirrored packages the better answer is
// forwarding the upstream signature unchanged; this package is for the
// packages bodega originates, where there is none to forward.
package aptsign

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// Signer is everything the apt index generator needs from a signing key. Only
// KeyRing implements it today; the interface is here so an off-box signer (an
// HSM, a remote signing service) drops in without touching the generator.
type Signer interface {
	// ClearSign wraps msg in a clearsigned document — apt's InRelease.
	ClearSign(msg []byte) ([]byte, error)
	// DetachSign returns an armored detached signature over msg — apt's
	// Release.gpg.
	DetachSign(msg []byte) ([]byte, error)
	// PublicKey returns the armored public key, for signed-by= after a
	// gpg --dearmor, and for humans.
	PublicKey() ([]byte, error)
	// Keyring returns the same keys dearmored, so signed-by= can point at
	// the served bytes with no gpg binary on the client.
	Keyring() ([]byte, error)
	// Fingerprints lists the primary key fingerprints, uppercase hex, in
	// load order. Publish these out of band: they are the only thing that
	// authenticates the first key fetch beyond TLS.
	Fingerprints() []string
}

// KeyFileName is the basename the signing key carries in every search
// location, so the systemd credential, /etc/bodega and storage_path all agree.
const KeyFileName = "apt-signing.key"

// SystemKeyPath is the packaged location for a key not delivered as a
// systemd credential.
//
// A var rather than a const so a test can determine the whole search order.
// Position 1 is an environment variable and position 3 derives from config, so
// this was the one entry a test could not steer, and a test that could not
// steer it passed or failed on whether the host running it had bodega
// installed. Nothing outside a test ever assigns it.
var SystemKeyPath = "/etc/bodega/" + KeyFileName

// CredentialsEnv is the directory systemd's LoadCredential= populates. It is a
// per-service tmpfs the unit itself cannot write and other services cannot
// read, which is why it is searched first.
const CredentialsEnv = "CREDENTIALS_DIRECTORY"

// ErrNoKey reports that no key exists at any searched path. It is not a
// failure: an unsigned repository is a supported configuration, so the server
// distinguishes this from a key that is present and unusable.
var ErrNoKey = errors.New("no apt signing key found")

// hashAlgo is set explicitly rather than left to the library default. apt's
// gpgv rejects SHA-1 signatures on current releases, and "whatever the library
// picks" is not a property this repository's clients can depend on.
const hashAlgo = crypto.SHA512

// KeyRing is an in-process Signer over one or more OpenPGP keys held in
// memory.
//
// Plural from the start because rotation needs it: apt accepts an InRelease
// when any one signature verifies, so a rotation window signs with both the
// outgoing and incoming key and publishes both public keys. A single-key
// signer would have to change shape to grow that.
type KeyRing struct {
	path     string
	entities openpgp.EntityList
}

// KeyInfo describes one loaded key for `bodega apt key show`.
type KeyInfo struct {
	Fingerprint string
	UserID      string
	Algorithm   string
	Created     time.Time
	Bits        uint16
}

// DefaultKeyPaths is the search order for the signing key: the systemd
// credential first, then the packaged system path, then a file beside the
// artifacts. storagePath may be empty, which drops the last entry.
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
// which is a read-only tmpfs. Key generation writes to the first of these it
// can create.
func WritablePaths(storagePath string) []string {
	paths := []string{SystemKeyPath}
	if storagePath != "" {
		paths = append(paths, filepath.Join(storagePath, KeyFileName))
	}
	return paths
}

// Load reads the first key file that exists, in the order given. A file that
// exists but cannot be parsed is an error rather than a skip: silently falling
// through to the next path would publish an unsigned repository while the
// operator believes a key is installed.
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

// LoadPath reads one key file.
func LoadPath(path string) (*KeyRing, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	// A signing key readable by anyone but its owner is a key you have to
	// assume is copied. Refuse rather than warn: a warning in a journal
	// nobody reads is how an 0644 key survives to the next audit.
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return nil, fmt.Errorf("apt signing key %s is mode %#o and readable beyond its owner; run chmod 600 %s", path, mode, path)
	}
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied path from the documented search order
	if err != nil {
		return nil, err
	}
	entities, err := readEntities(data)
	if err != nil {
		return nil, fmt.Errorf("parse apt signing key %s: %w", path, err)
	}
	if len(entities) == 0 {
		return nil, fmt.Errorf("apt signing key %s contains no keys", path)
	}
	for _, e := range entities {
		if e.PrivateKey == nil {
			return nil, fmt.Errorf("apt signing key %s holds a public key only; export the secret key", path)
		}
		if e.PrivateKey.Encrypted {
			return nil, fmt.Errorf("apt signing key %s is passphrase-protected; bodega runs unattended and cannot prompt — export it without a passphrase and protect it with file permissions instead", path)
		}
	}
	return &KeyRing{path: path, entities: entities}, nil
}

// readEntities parses one or more concatenated armored key blocks, falling
// back to a raw packet stream. gpg --export-secret-keys of two keys emits two
// blocks, and appending the incoming key to the file is how a rotation window
// is opened, so a single-block reader would silently drop the second key.
func readEntities(data []byte) (openpgp.EntityList, error) {
	const header = "-----BEGIN PGP"
	if !bytes.Contains(data, []byte(header)) {
		return openpgp.ReadKeyRing(bytes.NewReader(data))
	}
	var all openpgp.EntityList
	rest := data
	for {
		start := bytes.Index(rest, []byte(header))
		if start < 0 {
			break
		}
		rest = rest[start:]
		next := bytes.Index(rest[len(header):], []byte(header))
		block := rest
		if next >= 0 {
			block = rest[:len(header)+next]
			rest = rest[len(header)+next:]
		} else {
			rest = nil
		}
		el, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(block))
		if err != nil {
			return nil, err
		}
		all = append(all, el...)
		if rest == nil {
			break
		}
	}
	return all, nil
}

// Path reports the file this key ring was read from, for the startup log.
func (k *KeyRing) Path() string { return k.path }

// Len reports how many keys sign and are published.
func (k *KeyRing) Len() int { return len(k.entities) }

// config returns the packet config every signature is produced under.
func (k *KeyRing) config() *packet.Config {
	return &packet.Config{DefaultHash: hashAlgo}
}

// signingKeys resolves each entity's signing key, preferring a signing subkey
// the way gpg does.
func (k *KeyRing) signingKeys() ([]*packet.PrivateKey, error) {
	now := time.Now()
	keys := make([]*packet.PrivateKey, 0, len(k.entities))
	for _, e := range k.entities {
		sk, ok := e.SigningKey(now)
		if !ok || sk.PrivateKey == nil {
			return nil, fmt.Errorf("key %s has no usable signing key (expired, revoked, or encryption-only)", fingerprint(e))
		}
		keys = append(keys, sk.PrivateKey)
	}
	return keys, nil
}

// ClearSign produces InRelease. The enclosed body is byte-identical to msg, so
// a client that strips the armor gets the same Release the unsigned route
// serves.
func (k *KeyRing) ClearSign(msg []byte) ([]byte, error) {
	keys, err := k.signingKeys()
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	w, err := clearsign.EncodeMulti(&buf, keys, k.config())
	if err != nil {
		return nil, fmt.Errorf("clearsign: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return nil, fmt.Errorf("clearsign write: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("clearsign close: %w", err)
	}
	out, err := reArmorSignature(buf.Bytes())
	if err != nil {
		return nil, err
	}
	return out, nil
}

// reArmorSignature replaces the signature block of a clearsigned document with
// the same packets armored by armor.Encode, whose blocks carry the CRC24
// footer. clearsign asks for a block without one — RFC 9580 made the footer
// optional and go-crypto hardcodes it off — and gpgv 2.4.4, which is what
// Ubuntu 24.04 ships, reads the -----END dashes as base64 payload and exits 2
// after reporting a good signature for every key (#214). The message body
// ahead of the block is untouched, so the enclosed Release stays byte-identical
// to the one the unsigned route serves.
func reArmorSignature(doc []byte) ([]byte, error) {
	i := bytes.Index(doc, []byte("-----BEGIN PGP SIGNATURE-----"))
	if i < 0 {
		return nil, errors.New("clearsign produced no signature block")
	}
	block, err := armor.Decode(bytes.NewReader(doc[i:]))
	if err != nil {
		return nil, fmt.Errorf("decode clearsign armor: %w", err)
	}
	sigs, err := io.ReadAll(block.Body)
	if err != nil {
		return nil, fmt.Errorf("read clearsign armor: %w", err)
	}
	armored, err := armorBytes("PGP SIGNATURE", sigs)
	if err != nil {
		return nil, err
	}
	return append(doc[:i:i], armored...), nil
}

// DetachSign produces Release.gpg. Every key's signature goes into one armor
// block: apt accepts the file when at least one signature is good and none is
// bad, and a signature from a key the client has not installed yet reports as
// NO_PUBKEY rather than BADSIG. That is what makes a rotation window work.
func (k *KeyRing) DetachSign(msg []byte) ([]byte, error) {
	var sigs bytes.Buffer
	for _, e := range k.entities {
		if err := openpgp.DetachSign(&sigs, e, bytes.NewReader(msg), k.config()); err != nil {
			return nil, fmt.Errorf("detached signature from %s: %w", fingerprint(e), err)
		}
	}
	return armorBytes("PGP SIGNATURE", sigs.Bytes())
}

// PublicKey returns every loaded key's public half in one armored block.
func (k *KeyRing) PublicKey() ([]byte, error) {
	raw, err := k.Keyring()
	if err != nil {
		return nil, err
	}
	return armorBytes(openpgp.PublicKeyType, raw)
}

// Keyring returns the same public keys dearmored, which is the form
// /etc/apt/keyrings/ wants. Serving it means a client needs no gpg binary to
// consume signed-by=.
func (k *KeyRing) Keyring() ([]byte, error) {
	var buf bytes.Buffer
	for _, e := range k.entities {
		if err := e.Serialize(&buf); err != nil {
			return nil, fmt.Errorf("serialize public key %s: %w", fingerprint(e), err)
		}
	}
	return buf.Bytes(), nil
}

// Fingerprints lists the primary key fingerprints in load order.
func (k *KeyRing) Fingerprints() []string {
	out := make([]string, 0, len(k.entities))
	for _, e := range k.entities {
		out = append(out, fingerprint(e))
	}
	return out
}

// Keys describes each loaded key for display.
func (k *KeyRing) Keys() []KeyInfo {
	out := make([]KeyInfo, 0, len(k.entities))
	for _, e := range k.entities {
		info := KeyInfo{
			Fingerprint: fingerprint(e),
			Algorithm:   algorithmName(e.PrimaryKey.PubKeyAlgo),
			Created:     e.PrimaryKey.CreationTime,
		}
		if bits, err := e.PrimaryKey.BitLength(); err == nil {
			info.Bits = bits
		}
		if id := e.PrimaryIdentity(); id != nil {
			info.UserID = id.Name
		}
		out = append(out, info)
	}
	return out
}

func armorBytes(blockType string, raw []byte) ([]byte, error) {
	var out bytes.Buffer
	w, err := armor.Encode(&out, blockType, nil)
	if err != nil {
		return nil, fmt.Errorf("armor %s: %w", blockType, err)
	}
	if _, err := w.Write(raw); err != nil {
		return nil, fmt.Errorf("armor %s: %w", blockType, err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("armor %s: %w", blockType, err)
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}

func fingerprint(e *openpgp.Entity) string {
	return strings.ToUpper(hex.EncodeToString(e.PrimaryKey.Fingerprint))
}

func algorithmName(a packet.PublicKeyAlgorithm) string {
	switch a {
	case packet.PubKeyAlgoRSA, packet.PubKeyAlgoRSASignOnly:
		return "rsa"
	case packet.PubKeyAlgoEdDSA:
		return "ed25519"
	case packet.PubKeyAlgoEd25519:
		return "ed25519"
	case packet.PubKeyAlgoECDSA:
		return "ecdsa"
	default:
		return fmt.Sprintf("algo-%d", a)
	}
}
