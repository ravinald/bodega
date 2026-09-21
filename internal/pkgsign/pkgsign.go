// Package pkgsign signs a FreeBSD pkg catalogue bodega generated.
//
// What a signature here proves is narrow and has to be said out loud, because
// the type it belongs to spends most of its time doing the opposite. A
// mirrored repository is copied byte for byte precisely so FreeBSD's own
// signature reaches the client inside packagesite.pkg, and bodega signs
// nothing. This package is for the other case: packages an operator built —
// out of poudriere, or by hand — for which no upstream catalogue exists to
// copy. Regenerating a catalogue discards upstream's attestation permanently,
// so a repository bodega signs is one whose client is trusting this mirror
// and not FreeBSD.
//
// The shape is internal/aptsign's: an interface an off-box signer can satisfy,
// a key the operator creates with the CLI and the server only ever loads, and
// a search order that puts a systemd credential first. The algorithms are not.
// apt signing is OpenPGP; pkg's is a bare public-key signature over a hash the
// signing algorithm chooses, and the two share no primitive.
package pkgsign

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/blake2b"
)

// Signer is everything the catalogue generator needs from a signing key. Only
// KeyRing implements it today; the interface is here so an off-box signer (an
// HSM, a remote signing service) drops in without touching the generator.
type Signer interface {
	// Sign returns the signature bytes for the .sig member of an archive,
	// over the hash Algorithm names rather than over a hash the caller
	// picked.
	Sign(doc []byte) ([]byte, error)
	// PublicKey returns the PEM public key, which is both the .pub member
	// and the file a client names in pubkey= under signature_type: PUBKEY.
	PublicKey() ([]byte, error)
	// Algorithm is pkg's own name for the signer: "rsa" or "eddsa".
	Algorithm() string
	// Fingerprint is the SHA-256 of the PEM public key, lowercase hex. It is
	// the value a client writes into a trusted fingerprint file, and the only
	// thing that authenticates the first key fetch beyond TLS.
	Fingerprint() string
}

// KeyType names a generation algorithm, spelled as pkg spells it.
type KeyType string

const (
	// KeyRSA is the default. Every pkg since 1.x reads an RSA signature, and
	// a repository an operator is standing up has no way to know how old the
	// oldest client in the fleet is.
	KeyRSA KeyType = "rsa"
	// KeyEd25519 needs pkg 1.20 or later, which is where the ecc signer
	// arrived. Smaller keys and signatures, and nothing else changes.
	KeyEd25519 KeyType = "eddsa"
)

// KeyFileName is the basename the signing key carries in every search
// location, so the systemd credential, /etc/bodega and storage_path all agree.
// Named for pkg rather than for FreeBSD: it signs a pkg repository, and the
// apt key beside it is spelled the same way.
const KeyFileName = "pkg-signing.key"

// SystemKeyPath is the packaged location for a key not delivered as a systemd
// credential.
//
// A var rather than a const so a test can determine the whole search order.
// Position 1 is an environment variable and position 3 derives from config, so
// this is the one entry a test could not otherwise steer, and a test that
// cannot steer it passes or fails on whether the host running it has bodega
// installed. Nothing outside a test ever assigns it.
var SystemKeyPath = "/etc/bodega/" + KeyFileName

// CredentialsEnv is the directory systemd's LoadCredential= populates. It is a
// per-service tmpfs the unit itself cannot write and other services cannot
// read, which is why it is searched first.
const CredentialsEnv = "CREDENTIALS_DIRECTORY"

// ErrNoKey reports that no key exists at any searched path. It is not a
// failure: an unsigned pkg repository is a supported configuration — pkg's own
// signature_type defaults to NONE — so the server distinguishes this from a
// key that is present and unusable.
var ErrNoKey = errors.New("no pkg signing key found")

// eddsaPrefix frames an ecc signature the way pkg's pkgsign_ecc writes it:
// the magic, the signer name, and a "$" ahead of the raw signature, so a
// client reading the .sig member knows which verifier to hand it to. RSA
// carries no frame, which is what a pkg predating the ecc signer expects.
const eddsaPrefix = "$PKGSIGN:eddsa$"

// KeyRing is an in-process Signer over one private key.
//
// Singular, where aptsign's is plural, and the difference is a fact about the
// format rather than a simplification. apt accepts an InRelease when any one
// of several signatures verifies, so a rotation window signs twice. A pkg
// archive carries exactly one .sig and one .pub member, so there is no second
// signature to publish: a pkg rotation is the client trusting two
// fingerprints for a while, and it happens in the client's fingerprint
// directory rather than here.
type KeyRing struct {
	path string
	algo KeyType
	key  crypto.Signer
	pub  []byte // PEM SubjectPublicKeyInfo, rendered once at load
}

// KeyInfo describes the loaded key for `bodega freebsd key show`.
type KeyInfo struct {
	Fingerprint string
	Algorithm   string
	Bits        int
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

// inCredentialsDir reports whether path is a file systemd placed in this
// service's credential directory.
//
// The boundary is checked with a separator rather than a prefix so a sibling
// directory sharing the name's opening characters is outside, and both sides
// are cleaned first so ".." cannot walk out and back in. An unset or relative
// CREDENTIALS_DIRECTORY exempts nothing: systemd always sets an absolute path,
// so anything else is a caller's environment rather than systemd's, and "/"
// would exempt the entire filesystem.
func inCredentialsDir(path string) bool {
	dir := os.Getenv(CredentialsEnv)
	if dir == "" || !filepath.IsAbs(dir) || filepath.Clean(dir) == string(filepath.Separator) {
		return false
	}
	return strings.HasPrefix(filepath.Clean(path), filepath.Clean(dir)+string(filepath.Separator))
}

// Load reads the first key file that exists, in the order given. A file that
// exists but cannot be parsed is an error rather than a skip: falling through
// to the next path would publish an unsigned repository while the operator
// believes a key is installed, and pkg reports an unsigned repository as
// nothing at all.
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
	//
	// The group bit alone is forgiven inside $CREDENTIALS_DIRECTORY, because
	// systemd writes a LoadCredential= file 0440 root:root with an ACL for
	// the service user, on a read-only tmpfs where 0600 is a mode nothing can
	// set. World-readable stays refused everywhere, that directory included:
	// systemd never writes 0004, so a key carrying it there was put there by
	// something else.
	mode := info.Mode().Perm()
	if mode&0o007 != 0 || (mode&0o070 != 0 && !inCredentialsDir(path)) {
		return nil, fmt.Errorf("pkg signing key %s is mode %#o and readable beyond its owner; run chmod 600 %s", path, mode, path)
	}
	data, err := os.ReadFile(path) //nolint:gosec // operator-supplied path from the documented search order
	if err != nil {
		return nil, err
	}
	return parsePrivate(path, data)
}

// parsePrivate reads a PEM private key and resolves which pkg signer it is.
func parsePrivate(path string, data []byte) (*KeyRing, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("pkg signing key %s is not PEM; export it with `bodega freebsd key generate` or `openssl genrsa -out %s 4096`", path, path)
	}
	if strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED") || strings.Contains(block.Type, "ENCRYPTED") {
		return nil, fmt.Errorf("pkg signing key %s is passphrase-protected; bodega runs unattended and cannot prompt — export it without a passphrase and protect it with file permissions instead", path)
	}
	key, err := parseAnyPrivate(block)
	if err != nil {
		return nil, fmt.Errorf("parse pkg signing key %s: %w", path, err)
	}
	kr, err := newKeyRing(key)
	if err != nil {
		return nil, fmt.Errorf("pkg signing key %s: %w", path, err)
	}
	kr.path = path
	return kr, nil
}

// parseAnyPrivate accepts the three PEM bodies openssl and Go emit for the key
// types pkg verifies. An operator who already has a repository key made it
// with openssl, and "BEGIN RSA PRIVATE KEY" is what openssl genrsa writes.
func parseAnyPrivate(block *pem.Block) (crypto.Signer, error) {
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("the PEM body holds a %T, which cannot sign", key)
		}
		return signer, nil
	case "EC PRIVATE KEY":
		return nil, errors.New("this is an ECDSA key, and bodega signs a pkg catalogue with rsa or eddsa; generate one with `bodega freebsd key generate`")
	}
	return nil, fmt.Errorf("the PEM block is %q rather than a private key", block.Type)
}

// newKeyRing binds a parsed key to the pkg signer that owns it, which is what
// decides the hash the signature is taken over.
func newKeyRing(key crypto.Signer) (*KeyRing, error) {
	kr := &KeyRing{key: key}
	pub := key.Public()
	switch pub.(type) {
	case *rsa.PublicKey:
		kr.algo = KeyRSA
	case ed25519.PublicKey:
		kr.algo = KeyEd25519
	default:
		return nil, fmt.Errorf("a %T signs no pkg catalogue; pkg reads rsa and eddsa", pub)
	}
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, fmt.Errorf("render the public key: %w", err)
	}
	kr.pub = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return kr, nil
}

// Path reports the file this key was read from, for the startup log.
func (k *KeyRing) Path() string { return k.path }

// Algorithm is pkg's name for this signer.
func (k *KeyRing) Algorithm() string { return string(k.algo) }

// PublicKey returns the PEM public key: the .pub member of every archive this
// key signs, and the file a client names in pubkey=.
func (k *KeyRing) PublicKey() ([]byte, error) {
	if len(k.pub) == 0 {
		return nil, errors.New("this key ring holds no public key")
	}
	return k.pub, nil
}

// Fingerprint is the SHA-256 of the PEM public key, lowercase hex — the value
// that goes in a client's trusted fingerprint file under
// /usr/local/etc/pkg/fingerprints/bodega/trusted/.
func (k *KeyRing) Fingerprint() string {
	sum := sha256.Sum256(k.pub)
	return hex.EncodeToString(sum[:])
}

// Info describes the loaded key for display.
func (k *KeyRing) Info() KeyInfo {
	info := KeyInfo{Fingerprint: k.Fingerprint(), Algorithm: string(k.algo)}
	if rk, ok := k.key.Public().(*rsa.PublicKey); ok {
		info.Bits = rk.N.BitLen()
	}
	return info
}

// Sign returns the signature bytes pkg expects in the .sig member.
//
// The hash comes from the algorithm and never from the caller, which is the
// whole reason this is one method rather than a hash plus a sign. pkg's RSA
// signer takes the SHA-256 of the document, renders it as a 64-character
// lowercase hex string, and signs those characters with PKCS#1 v1.5 padding
// and no DigestInfo — an interoperability quirk, and one a client reproduces
// exactly. Its ecc signer takes a raw BLAKE2b-512 digest instead. An eddsa key
// over a SHA-256 produces a signature the client rejects with no clue as to
// why, so the pairing is not a caller's to choose.
func (k *KeyRing) Sign(doc []byte) ([]byte, error) {
	switch k.algo {
	case KeyRSA:
		rk, ok := k.key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is marked rsa but holds a %T", k.key)
		}
		sig, err := rsa.SignPKCS1v15(rand.Reader, rk, 0, rsaDigest(doc))
		if err != nil {
			return nil, fmt.Errorf("sign the catalogue with the rsa key: %w", err)
		}
		return sig, nil
	case KeyEd25519:
		ek, ok := k.key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is marked eddsa but holds a %T", k.key)
		}
		digest := blake2b.Sum512(doc)
		return append([]byte(eddsaPrefix), ed25519.Sign(ek, digest[:])...), nil
	}
	return nil, fmt.Errorf("no signer for key type %q", k.algo)
}

// rsaDigest is the message pkg's RSA signer actually signs: the hex rendering
// of the document's SHA-256, as characters.
func rsaDigest(doc []byte) []byte {
	sum := sha256.Sum256(doc)
	return []byte(hex.EncodeToString(sum[:]))
}

// Verify checks sig against doc under the PEM public key pubPEM, resolving the
// algorithm from the key rather than from an argument.
//
// The generator calls it on every catalogue it builds, before serving one
// byte. A signature nothing verified is a signature discovered to be wrong by
// a client, days later, reported as a repository failure with no mention of
// the key that produced it — and the check costs one public-key operation per
// rebuild.
func Verify(pubPEM, doc, sig []byte) error {
	block, _ := pem.Decode(pubPEM)
	if block == nil {
		return errors.New("the public key is not PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse the public key: %w", err)
	}
	switch pk := pub.(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(pk, 0, rsaDigest(doc), sig); err != nil {
			return fmt.Errorf("the rsa signature does not verify against this public key: %w", err)
		}
		return nil
	case ed25519.PublicKey:
		raw, ok := strings.CutPrefix(string(sig), eddsaPrefix)
		if !ok {
			return fmt.Errorf("the signature carries no %q frame, so it was not produced by an eddsa key", eddsaPrefix)
		}
		digest := blake2b.Sum512(doc)
		if !ed25519.Verify(pk, digest[:], []byte(raw)) {
			return errors.New("the eddsa signature does not verify against this public key")
		}
		return nil
	}
	return fmt.Errorf("a %T verifies no pkg signature", pub)
}
