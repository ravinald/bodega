package provenance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/url"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"gopkg.in/yaml.v3"

	"github.com/ravinald/bodega/internal/audit"
)

// MaxHelmProvBytes caps a chart's .prov file, which is the chart's Chart.yaml
// and one digest line under a signature: a few kilobytes in practice.
// MaxHelmChartBytes caps the chart archive the check downloads to digest when
// the entry records no sha256. Both are refused past the cap rather than
// truncated, since a truncated document reads as a different one.
const (
	MaxHelmProvBytes  = 1 << 20
	MaxHelmChartBytes = 64 << 20
)

var helmProvDigest = regexp.MustCompile(`^sha256:[0-9a-fA-F]{64}$`)

// LoadHelmKeyring reads the OpenPGP public keyring a helm_keyrings entry
// names, binary (gpg --export) or armored (gpg --export --armor). prefix is
// the helm_keyrings key the path was configured under, named in every error
// when it is not empty.
//
// The file decides which chart signatures verify, so one anybody but its
// owner can write is refused, and so is one carrying private key material,
// which verifying never needs and which should not sit where the server reads.
func LoadHelmKeyring(file, prefix string) (openpgp.EntityList, error) {
	where := "helm keyring " + file
	if prefix != "" {
		where = fmt.Sprintf("helm_keyrings[%q]: keyring %s", prefix, file)
	}
	fi, err := os.Stat(file)
	if err != nil {
		return nil, fmt.Errorf("%s cannot be read: %v; export the publisher's public key there with `gpg --export {key ID} > %s`", where, err, file)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file (mode %s); point helm_keyrings at the keyring file itself", where, fi.Mode())
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return nil, fmt.Errorf("%s is writable by group or others (mode %04o), so whoever can write it decides which chart signatures verify; run `chmod go-w %s`", where, perm, file)
	}
	data, err := os.ReadFile(file) //nolint:gosec // G304: an operator-configured path.
	if err != nil {
		return nil, fmt.Errorf("%s cannot be read: %v; make it readable by the user bodega runs as", where, err)
	}
	keys, private, err := readKeyring(data)
	switch {
	case private:
		return nil, fmt.Errorf("%s holds private key material, which verifying a .prov never needs; replace it with the public key alone, `gpg --export {key ID} > %s`", where, file)
	case err != nil:
		return nil, fmt.Errorf("%s parses as neither a binary keyring (`gpg --export`) nor an armored one (`gpg --export --armor`): %v; export the publisher's public key again", where, err)
	case len(keys) == 0:
		return nil, fmt.Errorf("%s holds no public key; export the publisher's public key there with `gpg --export {key ID} > %s`", where, file)
	}
	return keys, nil
}

// readKeyring parses a binary or armored keyring and reports whether any key
// in it carries private material.
//
// Every byte of the file is accounted for: each armored block is decoded on
// its own, since armor.Decode stops at the first block's footer, and any bytes
// outside a block are read as a binary keyring. Reading only the armor would
// let a private key concatenated before, between or after the blocks load
// unseen.
func readKeyring(data []byte) (openpgp.EntityList, bool, error) {
	var keys openpgp.EntityList
	var parseErr error
	note := func(err error) {
		if parseErr == nil {
			parseErr = err
		}
	}
	segs := keyringSegments(data)
	for i, seg := range segs {
		label := fmt.Sprintf("armored block %d", i+1)
		raw := seg.data
		if !seg.armored {
			label = fmt.Sprintf("bytes outside any armored block (segment %d)", i+1)
			if len(segs) == 1 {
				label = "binary keyring"
			}
		} else {
			blk, err := armor.Decode(bytes.NewReader(seg.data))
			if err != nil {
				return nil, false, fmt.Errorf("%s: %w", label, err)
			}
			if blk.Type == openpgp.PrivateKeyType {
				return nil, true, nil
			}
			body, err := io.ReadAll(blk.Body)
			if err != nil {
				return nil, false, fmt.Errorf("%s: %w", label, err)
			}
			if blk.Type != openpgp.PublicKeyType {
				if packetsHoldPrivate(body) {
					return nil, true, nil
				}
				note(fmt.Errorf("%s is a %q, not a %q", label, blk.Type, openpgp.PublicKeyType))
				continue
			}
			raw = body
		}
		if packetsHoldPrivate(raw) {
			return nil, true, nil
		}
		got, err := openpgp.ReadKeyRing(bytes.NewReader(raw))
		if trimmed := bytes.TrimRight(raw, " \t\r\n"); err != nil && !seg.armored && len(trimmed) < len(raw) {
			got, err = openpgp.ReadKeyRing(bytes.NewReader(trimmed))
		}
		if err != nil {
			note(fmt.Errorf("%s: %w", label, err))
			continue
		}
		if holdsPrivate(got) {
			return nil, true, nil
		}
		keys = append(keys, got...)
	}
	if parseErr != nil {
		return nil, false, parseErr
	}
	return keys, false, nil
}

var (
	armorBegin  = []byte("-----BEGIN PGP")
	armorEnd    = []byte("-----END PGP")
	armorDashes = []byte("-----")
)

type keyringSegment struct {
	data    []byte
	armored bool
}

// keyringSegments splits data into armored blocks, each running from its
// header through its footer, and the bytes between them. Whitespace
// between blocks is not a segment; anything else is.
func keyringSegments(data []byte) []keyringSegment {
	var out []keyringSegment
	// A packet's tag byte has its high bit set, so leading whitespace is
	// never packet data. Trailing whitespace can be, and readKeyring retries
	// without it rather than trimming it here.
	addBinary := func(b []byte) {
		if b = bytes.TrimLeft(b, " \t\r\n"); len(b) > 0 {
			out = append(out, keyringSegment{data: b})
		}
	}
	for len(data) > 0 {
		start := bytes.Index(data, armorBegin)
		if start < 0 {
			addBinary(data)
			break
		}
		addBinary(data[:start])
		data = data[start:]
		end := len(data)
		if e := bytes.Index(data, armorEnd); e >= 0 {
			// The footer ends at its closing dashes, not at a newline:
			// encoders write none after it, so whatever follows may start on
			// the same line.
			end = e + len(armorEnd)
			if c := bytes.Index(data[end:], armorDashes); c >= 0 {
				end += c + len(armorDashes)
			} else {
				end = len(data)
			}
		}
		out = append(out, keyringSegment{data: data[:end], armored: true})
		data = data[end:]
	}
	return out
}

// packetsHoldPrivate reports whether any packet in b is a secret key, read
// packet by packet so private material is found even where the packets do
// not form a keyring ReadKeyRing would accept.
func packetsHoldPrivate(b []byte) bool {
	r := packet.NewReader(bytes.NewReader(b))
	for {
		p, err := r.Next()
		if err != nil {
			return false
		}
		if _, ok := p.(*packet.PrivateKey); ok {
			return true
		}
	}
}

func holdsPrivate(keys openpgp.EntityList) bool {
	for _, e := range keys {
		if e.PrivateKey != nil {
			return true
		}
		for _, sub := range e.Subkeys {
			if sub.PrivateKey != nil {
				return true
			}
		}
	}
	return false
}

// helmChartURL is the chart archive an entry names: its url when that is the
// archive itself, otherwise the archive under the repository base url names,
// composed the way the proxy composes it.
func helmChartURL(entryURL, name, version string) string {
	if strings.HasSuffix(entryURL, ".tgz") {
		return entryURL
	}
	return strings.TrimSuffix(entryURL, "/") + "/" + name + "-" + version + ".tgz"
}

// helmKeyringFor is the longest helm_keyrings prefix chartURL starts with,
// and the keyring it names.
func (v *Verifier) helmKeyringFor(chartURL string) (prefix, file string) {
	for p, f := range v.HelmKeyrings {
		if strings.HasPrefix(chartURL, p) && len(p) > len(prefix) {
			prefix, file = p, f
		}
	}
	return prefix, file
}

// Helm verifies the .prov file a classic chart repository publishes beside a
// chart: its clearsigned signature against the keyring helm_keyrings names for
// the chart's repository, then the sha256 it signs for the chart archive
// against entryDigest, or against the archive itself when the entry records
// none.
func (v *Verifier) Helm(ctx context.Context, name, version, entryURL, entryDigest string) Evidence {
	if strings.Contains(name, "/") {
		return unavailable("bodega does not read the provenance layer of a chart served over OCI yet")
	}
	if entryURL == "" {
		return unavailable("the entry names no chart URL to read a .prov beside")
	}
	chartURL := helmChartURL(entryURL, name, version)
	provURL := chartURL + ".prov"
	file := path.Base(chartURL)
	if u, err := url.Parse(chartURL); err == nil {
		file = path.Base(u.Path)
	}

	raw, err := v.get(ctx, provURL, nil, MaxHelmProvBytes)
	switch {
	case errors.Is(err, errNotFound):
		return unavailable("%s is not published (HTTP 404), so the chart carries no publisher signature", provURL)
	case err != nil:
		return unknown("reading %s failed, so whether the chart is signed is unknown: %v", provURL, err)
	}
	block, _ := clearsign.Decode(raw)
	if block == nil {
		return unknown("%s is not an OpenPGP clearsigned message, so nothing signed was read", provURL)
	}
	sig, err := io.ReadAll(block.ArmoredSignature.Body)
	if err != nil {
		return unknown("%s carries a signature block that does not decode, so nothing signed was read: %v", provURL, err)
	}
	keyID, err := signingKeyID(sig)
	if err != nil {
		return unknown("%s carries no readable signature packet, so nothing signed was read: %v", provURL, err)
	}

	prefix, keyringFile := v.helmKeyringFor(chartURL)
	if prefix == "" {
		ev := unknown("%s is signed by key %s, and helm_keyrings names no keyring for this repository, so the signature was not checked; add the publisher's public key under a helm_keyrings prefix that matches %s", provURL, keyID, chartURL)
		ev.NoKeyring = true
		return ev
	}
	keyring, err := LoadHelmKeyring(keyringFile, prefix)
	if err != nil {
		return unknown("%s is signed by key %s and was not checked: %v", provURL, keyID, err)
	}
	_, signer, err := openpgp.VerifyDetachedSignature(keyring, bytes.NewReader(block.Bytes), bytes.NewReader(sig), nil)
	if err != nil {
		return invalid("%s is signed by key %s and does not verify against keyring %s (helm_keyrings[%q]): %v; confirm with the publisher that it rotated its signing key, and if it did, add the new public key to %s, because an invalid result admits no override", provURL, keyID, keyringFile, prefix, err, keyringFile)
	}

	signed, err := helmProvDigestFor(block.Plaintext, file)
	if err != nil {
		return invalid("%s verified against keyring %s, but %v", provURL, keyringFile, err)
	}
	digest, source := entryDigest, "the entry records"
	if digest == "" {
		if digest, err = v.digestURL(ctx, chartURL, MaxHelmChartBytes); err != nil {
			return unknown("%s verified, but downloading %s to compare its digest failed: %v", provURL, chartURL, err)
		}
		source = "the archive at " + chartURL + " hashes to"
	}
	if "sha256:"+strings.ToLower(digest) != signed {
		return invalid("%s signs %s for %s, but %s sha256:%s, so the chart is not the one the publisher signed", provURL, signed, file, source, strings.ToLower(digest))
	}
	fpr := strings.ToUpper(hex.EncodeToString(signer.PrimaryKey.Fingerprint))
	return Evidence{
		UpstreamProvenance: audit.UpstreamProvenance{Outcome: audit.ProvenanceVerified, SignerFingerprint: fpr, SubjectDigest: signed},
		Detail:             fmt.Sprintf("%s is signed by %s, a key in %s (helm_keyrings[%q]), and covers %s at %s", provURL, fpr, keyringFile, prefix, file, signed),
	}
}

// signingKeyID is the issuer of a detached signature, read without a keyring
// so a signature nothing verifies can still be named.
func signingKeyID(sig []byte) (string, error) {
	p, err := packet.NewReader(bytes.NewReader(sig)).Next()
	if err != nil {
		return "", err
	}
	s, ok := p.(*packet.Signature)
	switch {
	case !ok:
		return "", fmt.Errorf("the first packet is a %T, not a signature", p)
	case s.IssuerKeyId != nil:
		return fmt.Sprintf("%016X", *s.IssuerKeyId), nil
	case len(s.IssuerFingerprint) > 0:
		return strings.ToUpper(hex.EncodeToString(s.IssuerFingerprint)), nil
	}
	return "", errors.New("the signature names no issuer")
}

// helmProvDigestFor reads the digest a .prov's signed text records for file.
// Helm writes the chart's Chart.yaml, a "..." line, then a files map; it
// splits on that line the same way.
func helmProvDigestFor(plaintext []byte, file string) (string, error) {
	text := bytes.ReplaceAll(plaintext, []byte("\r\n"), []byte("\n"))
	parts := bytes.SplitN(text, []byte("\n...\n"), 2)
	if len(parts) < 2 {
		return "", fmt.Errorf("its signed text has no \"...\" line before a files map, so it records no digest for %s", file)
	}
	var sums struct {
		Files map[string]string `yaml:"files"`
	}
	if err := yaml.Unmarshal(parts[1], &sums); err != nil {
		return "", fmt.Errorf("its files section does not parse as YAML, so it records no digest for %s: %v", file, err)
	}
	got, ok := sums.Files[file]
	if !ok {
		held := "nothing"
		if len(sums.Files) > 0 {
			held = strings.Join(slices.Sorted(maps.Keys(sums.Files)), ", ")
		}
		return "", fmt.Errorf("its files map has no entry for %s; it names %s", file, held)
	}
	if !helmProvDigest.MatchString(got) {
		return "", fmt.Errorf("its files entry for %s is %q, not sha256: followed by 64 hex digits", file, got)
	}
	return strings.ToLower(got), nil
}

// digestURL is the hex sha256 of what url serves, refusing a body over limit
// bytes rather than hashing a truncated one.
func (v *Verifier) digestURL(ctx context.Context, url string, limit int64) (string, error) {
	resp, err := v.open(ctx, url, nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return "", fmt.Errorf("GET %s: %w", url, err)
	}
	if n > limit {
		return "", fmt.Errorf("GET %s: the body is larger than the %d MiB cap", url, limit>>20)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
