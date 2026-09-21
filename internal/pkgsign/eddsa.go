package pkgsign

import (
	"crypto/ed25519"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
)

// pkg's ecc signer does not speak any encoding Go's standard library emits.
//
// Ed25519 everywhere else is a 32-byte compressed Edwards point and a 64-byte
// R||S signature. pkg's verifier is libecc, which holds every curve in short
// Weierstrass form, so it reads a public key as the affine (X, Y) of the same
// point on WEI25519 wrapped in a DER structure of pkg's own devising, and a
// signature as a DER sequence of two integers. Emitting SubjectPublicKeyInfo
// and a raw signature produces bytes that parse as neither.
//
// The translation is a birational map and its inverse, which is why this is
// arithmetic rather than a call: nothing in crypto/ed25519 exposes the affine
// coordinates, and no encoder in the standard library writes libecc's key.
//
// Determined against pkg 2.8.2 itself rather than from a specification: a key
// from `pkg key --create -t eddsa` maps to an Ed25519 public key that verifies
// a signature from `pkg key --sign`, which is what fixed the one free choice
// below (the sign of edwardsC) and what TestEdDSAMatchesPkgFixture holds.

// pkgPublicKeyInfo is the DER public key pkg's ecc signer reads, written by
// its own ecc_write_pkgkey and parsed by ecc_read_pkgkey.
//
// Signer is "ecc" rather than "eddsa" although the signature frame says
// eddsa: pkg names the implementation here and the algorithm there, and a key
// carrying the algorithm in this field is refused by a reader comparing it to
// the literal "ecc".
type pkgPublicKeyInfo struct {
	App     string `asn1:"utf8"`
	Version int
	Signer  string `asn1:"utf8"`
	KeyType string `asn1:"utf8"`
	Public  bool
	Key     asn1.BitString
}

const (
	pkgKeyApp    = "pkg"
	pkgKeySigner = "ecc"
	// pkgKeyCurve is libecc's name for the short Weierstrass form of
	// Curve25519, and the only one pkg's eddsa signer uses.
	pkgKeyCurve = "WEI25519"
	// pkgKeyVersion is the only version ecc_read_pkgkey accepts.
	pkgKeyVersion = 1
	// pointUncompressed is the SEC1 lead byte pkg writes ahead of the affine
	// coordinates. libecc reads no other form.
	pointUncompressed = 0x04
	// coordLen is the byte width of one WEI25519 coordinate.
	coordLen = 32
)

// Field constants for Curve25519 in its three forms. p and d are Ed25519's;
// montgomeryA is Curve25519's; edwardsC is the constant that relates the
// Edwards x to the Montgomery v.
var (
	fieldP      = mustInt("57896044618658097711785492504343953926634992332820282019728792003956564819949")
	edwardsD    = mustInt("37095705934669439343138083508754565189542113879843219016388785533085940283555")
	montgomeryA = big.NewInt(486662)

	// edwardsC is the square root of -486664 with the low bit set. Both roots
	// satisfy the curve equation and only one reproduces the point libecc
	// derives from the same private key; picking the other yields (X, -Y),
	// whose encoding changes the public key pkg hashes into every signature
	// and so fails verification with nothing naming the coordinate.
	edwardsC = mustInt("51042569399160536130206135233146329284152202253034631822681833788666877215207")
)

func mustInt(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("pkgsign: bad field constant " + s)
	}
	return n
}

func feAdd(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Add(a, b), fieldP) }
func feSub(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Sub(a, b), fieldP) }
func feMul(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Mul(a, b), fieldP) }

// feInv is the multiplicative inverse, or nil when a is zero mod p.
func feInv(a *big.Int) *big.Int { return new(big.Int).ModInverse(a, fieldP) }

// feSqrt returns a square root of a, or nil when a is not a residue. p is
// 5 mod 8, so the candidate needs a second try against sqrt(-1).
func feSqrt(a *big.Int) *big.Int {
	a = new(big.Int).Mod(a, fieldP)
	e := new(big.Int).Rsh(new(big.Int).Add(fieldP, big.NewInt(3)), 3)
	x := new(big.Int).Exp(a, e, fieldP)
	if feMul(x, x).Cmp(a) == 0 {
		return x
	}
	i := new(big.Int).Exp(big.NewInt(2), new(big.Int).Rsh(new(big.Int).Sub(fieldP, big.NewInt(1)), 2), fieldP)
	x = feMul(x, i)
	if feMul(x, x).Cmp(a) == 0 {
		return x
	}
	return nil
}

// edwardsPoint recovers the affine (x, y) of a compressed Ed25519 public key.
func edwardsPoint(pub ed25519.PublicKey) (x, y *big.Int, err error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, nil, fmt.Errorf("an ed25519 public key is %d bytes, not %d", ed25519.PublicKeySize, len(pub))
	}
	le := make([]byte, ed25519.PublicKeySize)
	for i, b := range pub {
		le[ed25519.PublicKeySize-1-i] = b
	}
	sign := le[0] >> 7
	le[0] &^= 0x80
	y = new(big.Int).SetBytes(le)
	if y.Cmp(fieldP) >= 0 {
		return nil, nil, errors.New("the public key's y coordinate is not reduced, so it is not a curve point")
	}
	// x^2 = (y^2 - 1) / (d*y^2 + 1)
	y2 := feMul(y, y)
	den := feInv(feAdd(feMul(edwardsD, y2), big.NewInt(1)))
	if den == nil {
		return nil, nil, errors.New("the public key's y coordinate has no matching x on the curve")
	}
	x = feSqrt(feMul(feSub(y2, big.NewInt(1)), den))
	if x == nil {
		return nil, nil, errors.New("the public key is not a point on the ed25519 curve")
	}
	if x.Sign() == 0 && sign == 1 {
		return nil, nil, errors.New("the public key encodes x = 0 with a negative sign, which is not a valid point")
	}
	if x.Bit(0) != uint(sign) {
		x = feSub(big.NewInt(0), x)
	}
	return x, y, nil
}

// weierstrassPoint is the WEI25519 affine point of an Ed25519 public key.
//
// Edwards to Montgomery is u = (1+y)/(1-y) and v = C*u/x; Montgomery to short
// Weierstrass is X = u + A/3 and Y = v, the curve's B being 1.
func weierstrassPoint(pub ed25519.PublicKey) (bigX, bigY *big.Int, err error) {
	x, y, err := edwardsPoint(pub)
	if err != nil {
		return nil, nil, err
	}
	den := feInv(feSub(big.NewInt(1), y))
	if den == nil || x.Sign() == 0 {
		// y = 1 is the identity and x = 0 is the point of order two. Neither
		// is a public key any keypair produces, and both divide by zero here.
		return nil, nil, errors.New("the public key is a low-order point and signs nothing")
	}
	u := feMul(feAdd(big.NewInt(1), y), den)
	v := feMul(feMul(edwardsC, u), feInv(x))
	a3 := feInv(big.NewInt(3))
	return feAdd(u, feMul(montgomeryA, a3)), v, nil
}

// edwardsPublicKey is weierstrassPoint's inverse, for reading a .pub member
// back.
func edwardsPublicKey(bigX, bigY *big.Int) (ed25519.PublicKey, error) {
	if bigX.Sign() < 0 || bigX.Cmp(fieldP) >= 0 || bigY.Sign() < 0 || bigY.Cmp(fieldP) >= 0 {
		return nil, errors.New("the public key's coordinates are not reduced, so they are not a curve point")
	}
	a3 := feInv(big.NewInt(3))
	u := feSub(bigX, feMul(montgomeryA, a3))
	den := feInv(feAdd(u, big.NewInt(1)))
	if den == nil || bigY.Sign() == 0 {
		return nil, errors.New("the public key is a low-order point and verifies nothing")
	}
	y := feMul(feSub(u, big.NewInt(1)), den)
	x := feMul(feMul(edwardsC, u), feInv(bigY))
	enc := make([]byte, ed25519.PublicKeySize)
	y.FillBytes(enc)
	for i, j := 0, len(enc)-1; i < j; i, j = i+1, j-1 {
		enc[i], enc[j] = enc[j], enc[i]
	}
	if x.Bit(0) == 1 {
		enc[ed25519.PublicKeySize-1] |= 0x80
	}
	return ed25519.PublicKey(enc), nil
}

// eddsaPublicKey renders the .pub member for an Ed25519 key.
func eddsaPublicKey(pub ed25519.PublicKey) ([]byte, error) {
	x, y, err := weierstrassPoint(pub)
	if err != nil {
		return nil, err
	}
	raw := make([]byte, 1+2*coordLen)
	raw[0] = pointUncompressed
	x.FillBytes(raw[1 : 1+coordLen])
	y.FillBytes(raw[1+coordLen:])
	return asn1.Marshal(pkgPublicKeyInfo{
		App:     pkgKeyApp,
		Version: pkgKeyVersion,
		Signer:  pkgKeySigner,
		KeyType: pkgKeyCurve,
		Public:  true,
		Key:     asn1.BitString{Bytes: raw, BitLength: len(raw) * 8},
	})
}

// parseEdDSAPublicKey reads a .pub member back into an Ed25519 public key.
func parseEdDSAPublicKey(der []byte) (ed25519.PublicKey, error) {
	var info pkgPublicKeyInfo
	rest, err := asn1.Unmarshal(der, &info)
	if err != nil {
		return nil, fmt.Errorf("the public key is not pkg's DER key structure: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("the public key carries %d trailing bytes", len(rest))
	}
	switch {
	case info.App != pkgKeyApp:
		return nil, fmt.Errorf("the public key names application %q rather than %q", info.App, pkgKeyApp)
	case info.Version != pkgKeyVersion:
		return nil, fmt.Errorf("the public key is version %d and pkg reads version %d", info.Version, pkgKeyVersion)
	case info.Signer != pkgKeySigner:
		return nil, fmt.Errorf("the public key names signer %q rather than %q", info.Signer, pkgKeySigner)
	case info.KeyType != pkgKeyCurve:
		return nil, fmt.Errorf("the public key names curve %q and bodega signs on %q", info.KeyType, pkgKeyCurve)
	case !info.Public:
		return nil, errors.New("the public key is marked private")
	case len(info.Key.Bytes) != 1+2*coordLen || info.Key.Bytes[0] != pointUncompressed:
		return nil, fmt.Errorf("the public key holds %d bytes of key material rather than an uncompressed %d-byte point", len(info.Key.Bytes), 1+2*coordLen)
	}
	return edwardsPublicKey(
		new(big.Int).SetBytes(info.Key.Bytes[1:1+coordLen]),
		new(big.Int).SetBytes(info.Key.Bytes[1+coordLen:]),
	)
}

// eddsaSignature frames a raw Ed25519 signature the way pkg reads one: the
// signer prefix, then R and S as a DER sequence of two integers.
func eddsaSignature(raw []byte) ([]byte, error) {
	if len(raw) != ed25519.SignatureSize {
		return nil, fmt.Errorf("an ed25519 signature is %d bytes, not %d", ed25519.SignatureSize, len(raw))
	}
	der, err := asn1.Marshal(struct{ R, S *big.Int }{
		R: new(big.Int).SetBytes(raw[:coordLen]),
		S: new(big.Int).SetBytes(raw[coordLen:]),
	})
	if err != nil {
		return nil, fmt.Errorf("encode the signature: %w", err)
	}
	return append([]byte(eddsaPrefix), der...), nil
}

// parseEdDSASignature is eddsaSignature's inverse.
//
// R and S are 32-byte strings that DER carries as integers, so a leading zero
// byte in either is dropped on the way out and has to be restored on the way
// back. pkg's own reader left-pads for the same reason.
func parseEdDSASignature(sig []byte) ([]byte, error) {
	body, ok := bytesCutPrefix(sig, eddsaPrefix)
	if !ok {
		return nil, fmt.Errorf("the signature carries no %q frame, so it was not produced by an eddsa key", eddsaPrefix)
	}
	var parts struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(body, &parts)
	if err != nil {
		return nil, fmt.Errorf("the signature is not a DER sequence of two integers: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("the signature carries %d trailing bytes", len(rest))
	}
	if parts.R.Sign() < 0 || parts.S.Sign() < 0 ||
		parts.R.BitLen() > coordLen*8 || parts.S.BitLen() > coordLen*8 {
		return nil, errors.New("the signature's halves do not fit a 32-byte coordinate each")
	}
	raw := make([]byte, ed25519.SignatureSize)
	parts.R.FillBytes(raw[:coordLen])
	parts.S.FillBytes(raw[coordLen:])
	return raw, nil
}

// bytesCutPrefix is strings.CutPrefix over bytes, kept here so the signature
// path never converts key-adjacent material to a string.
func bytesCutPrefix(b []byte, prefix string) ([]byte, bool) {
	if len(b) < len(prefix) || string(b[:len(prefix)]) != prefix {
		return nil, false
	}
	return b[len(prefix):], true
}
