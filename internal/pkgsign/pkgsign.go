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
)

// Signer is everything the catalogue generator needs from a signing key. Only
// KeyRing implements it today; the interface is here so an off-box signer (an
// HSM, a remote signing service) drops in without touching the generator.
type Signer interface {
	// Sign returns the signature bytes for the .sig member of an archive,
	// over the hash Algorithm names rather than over a hash the caller
	// picked.
	Sign(doc []byte) ([]byte, error)
	// PublicKey returns the public key as the client hashes it for a
	// fingerprint check, and as `bodega freebsd key export` prints it.
	PublicKey() ([]byte, error)
	// PublicKeyMember returns the bytes of the archive's .pub member, which
	// is PublicKey behind the same signer frame the .sig member carries.
	PublicKeyMember() ([]byte, error)
	// Algorithm is pkg's own name for the signer: "rsa" or "eddsa".
	Algorithm() string
	// Fingerprint is the SHA-256 of PublicKey, lowercase hex. It is the value
	// a client writes into a trusted fingerprint file, and the only thing
	// that authenticates the first key fetch beyond TLS.
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

// eddsaPrefix names the verifier a client hands the members to: the magic,
// the signer name, and a "$".
//
// It goes on the .pub member as well as the .sig, which is not an obvious
// symmetry and is not optional. pkg records the signer per member and keeps
// the last one it reads, so an unframed .pub following a framed .sig resets
// the choice to rsa and the ecc key reaches the OpenSSL verifier, which
// reports "error reading public key" and never names the member that caused
// it. pkg's own pack_command_sign writes the frame on both for this reason.
//
// The frame is not part of the key: a client strips it before hashing, so a
// fingerprint is taken over the bare key and PublicKey returns that form.
// RSA carries no frame at all, which is what a pkg predating the ecc signer
// expects.
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
	switch pub := key.Public().(type) {
	case *rsa.PublicKey:
		kr.algo = KeyRSA
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return nil, fmt.Errorf("render the public key: %w", err)
		}
		kr.pub = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	case ed25519.PublicKey:
		kr.algo = KeyEd25519
		der, err := eddsaPublicKey(pub)
		if err != nil {
			return nil, fmt.Errorf("render the public key: %w", err)
		}
		kr.pub = der
	default:
		return nil, fmt.Errorf("a %T signs no pkg catalogue; pkg reads rsa and eddsa", pub)
	}
	return kr, nil
}

// Path reports the file this key was read from, for the startup log.
func (k *KeyRing) Path() string { return k.path }

// Algorithm is pkg's name for this signer.
func (k *KeyRing) Algorithm() string { return string(k.algo) }

// PublicKey returns the public key in the form its signer's verifier reads: a
// PEM SubjectPublicKeyInfo for rsa, pkg's own DER structure for eddsa. It is
// what a client hashes for a fingerprint, and what the CLI exports.
func (k *KeyRing) PublicKey() ([]byte, error) {
	if len(k.pub) == 0 {
		return nil, errors.New("this key ring holds no public key")
	}
	return k.pub, nil
}

// PublicKeyMember is PublicKey framed for the archive's .pub member.
func (k *KeyRing) PublicKeyMember() ([]byte, error) {
	pub, err := k.PublicKey()
	if err != nil {
		return nil, err
	}
	if k.algo != KeyEd25519 {
		return pub, nil
	}
	return append([]byte(eddsaPrefix), pub...), nil
}

// Fingerprint is the SHA-256 of the public key, lowercase hex: the value that
// goes in a client's trusted fingerprint file under
// /usr/local/etc/pkg/fingerprints/bodega/trusted/.
//
// Over PublicKey rather than over the .pub member, because pkg strips the
// signer frame before hashing. A fingerprint taken over the framed bytes
// matches nothing a client computes, and the mismatch reports as an untrusted
// key rather than as a framing difference.
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
// whole reason this is one method rather than a hash plus a sign.
//
// The construction is pkgsign_ossl.c's ossl_verify_cert_cb, which is the
// verifier a three-member archive reaches: pkg hashes the document to SHA-256,
// renders that as 64 lowercase hex characters, takes the SHA-256 of those
// characters, and verifies PKCS#1 v1.5 with the SHA-256 DigestInfo over the
// resulting 32 bytes. Two hashes, and the second one is easy to miss because
// the first already produced something that looks like a digest.
//
// pkg's other RSA verifier, ossl_verify_cb, is a different construction
// reached only by signature_type: PUBKEY, which reads a member named
// "signature" that this archive does not carry. Nothing bodega publishes goes
// down that path.
func (k *KeyRing) Sign(doc []byte) ([]byte, error) {
	switch k.algo {
	case KeyRSA:
		rk, ok := k.key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is marked rsa but holds a %T", k.key)
		}
		digest := rsaDigest(doc)
		sig, err := rsa.SignPKCS1v15(rand.Reader, rk, crypto.SHA256, digest[:])
		if err != nil {
			return nil, fmt.Errorf("sign the catalogue with the rsa key: %w", err)
		}
		return sig, nil
	case KeyEd25519:
		ek, ok := k.key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is marked eddsa but holds a %T", k.key)
		}
		return eddsaSignature(ed25519.Sign(ek, eddsaDigest(doc)))
	}
	return nil, fmt.Errorf("no signer for key type %q", k.algo)
}

// eddsaDigest is the message pkg's ecc fingerprint verifier signs over: the
// document's SHA-256 rendered as 64 lowercase hex characters, signed as
// characters. ecc_verify_cert_cb hands exactly that to libecc.
//
// pkg's other ecc callback, ecc_verify_cb, hashes differently and belongs to
// an archive mode this generator does not produce.
func eddsaDigest(doc []byte) []byte {
	sum := sha256.Sum256(doc)
	return []byte(hex.EncodeToString(sum[:]))
}

// rsaDigest is the 32 bytes pkg's fingerprint verifier hands to RSA: the
// SHA-256 of the hex rendering of the document's SHA-256.
func rsaDigest(doc []byte) [sha256.Size]byte {
	sum := sha256.Sum256(doc)
	return sha256.Sum256([]byte(hex.EncodeToString(sum[:])))
}

// Verify checks sig against doc under the public key as the archive carries
// it, resolving the algorithm from the key's own encoding rather than from an
// argument.
//
// The encoding is the discriminator because pkg made it one: an rsa .pub
// member is a PEM SubjectPublicKeyInfo and an eddsa .pub member is pkg's own
// DER structure, and no key is both.
//
// The generator calls it on every catalogue it builds, before serving one
// byte. A signature nothing verified is a signature discovered to be wrong by
// a client, days later, reported as a repository failure with no mention of
// the key that produced it — and the check costs one public-key operation per
// rebuild.
func Verify(pubKey, doc, sig []byte) error {
	if block, _ := pem.Decode(pubKey); block != nil {
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse the public key: %w", err)
		}
		rk, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("a %T in a PEM block verifies no pkg signature; pkg reads a PEM public key for rsa only", pub)
		}
		digest := rsaDigest(doc)
		if err := rsa.VerifyPKCS1v15(rk, crypto.SHA256, digest[:], sig); err != nil {
			return fmt.Errorf("the rsa signature does not verify against this public key: %w", err)
		}
		return nil
	}
	if framed, ok := bytesCutPrefix(pubKey, eddsaPrefix); ok {
		pubKey = framed
	}
	pub, err := parseEdDSAPublicKey(pubKey)
	if err != nil {
		return err
	}
	raw, err := parseEdDSASignature(sig)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, eddsaDigest(doc), raw) {
		return errors.New("the eddsa signature does not verify against this public key")
	}
	return nil
}
