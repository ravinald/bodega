package builder

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/scaleapi/bodega/internal/manifest"
)

// computeFileSHA256 returns the lowercase hex SHA-256 digest of a file.
func computeFileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// computeBytesSHA256 returns the lowercase hex SHA-256 digest of a byte slice.
func ComputeBytesSHA256(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// verifyChecksum checks a computed SHA-256 against an entry's Checksum field.
// Returns nil if the checksum matches or is not set. Returns an error on mismatch.
func verifyChecksum(cs *manifest.Checksum, computed string) error {
	if cs == nil {
		return nil
	}
	if cs.Algorithm != "sha256" {
		return fmt.Errorf("unsupported checksum algorithm %q (only sha256 supported for verification)", cs.Algorithm)
	}
	if cs.Value != computed {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", cs.Value, computed)
	}
	return nil
}

// newSHA256Checksum creates a Checksum struct from a computed hex digest.
func newSHA256Checksum(hexDigest string) *manifest.Checksum {
	return &manifest.Checksum{
		Algorithm: "sha256",
		Value:     hexDigest,
	}
}

// findAndUpdateGitChecksum updates the Checksum and ChecksumVerified fields on a GitEntry and saves.
func (c *Config) findAndUpdateGitChecksum(store *manifest.Store, name string, cs *manifest.Checksum, verified bool) error {
	e := store.FindGit(name)
	if e == nil {
		return fmt.Errorf("git entry %q not found", name)
	}
	e.Checksum = cs
	e.ChecksumVerified = verified
	return store.SaveGit()
}

// findAndUpdateGomodChecksum updates the Checksum and ChecksumVerified fields on a GomodEntry and saves.
func (c *Config) findAndUpdateGomodChecksum(store *manifest.Store, name string, cs *manifest.Checksum, verified bool) error {
	e := store.FindGomod(name)
	if e == nil {
		return fmt.Errorf("gomod entry %q not found", name)
	}
	e.Checksum = cs
	e.ChecksumVerified = verified
	return store.SaveGomod()
}

// findAndUpdateHelmChecksum updates the Checksum and ChecksumVerified fields on a HelmEntry and saves.
func (c *Config) findAndUpdateHelmChecksum(store *manifest.Store, name string, cs *manifest.Checksum, verified bool) error {
	e := store.FindHelm(name)
	if e == nil {
		return fmt.Errorf("helm entry %q not found", name)
	}
	e.Checksum = cs
	e.ChecksumVerified = verified
	return store.SaveHelm()
}

// findAndUpdateNpmChecksum updates the Checksum and ChecksumVerified fields on an NpmEntry and saves.
func (c *Config) findAndUpdateNpmChecksum(store *manifest.Store, name string, cs *manifest.Checksum, verified bool) error {
	e := store.FindNpm(name)
	if e == nil {
		return fmt.Errorf("npm entry %q not found", name)
	}
	e.Checksum = cs
	e.ChecksumVerified = verified
	return store.SaveNpm()
}

// findAndUpdateBinaryChecksum updates the Checksum and ChecksumVerified fields on a BinaryEntry and saves.
func (c *Config) findAndUpdateBinaryChecksum(store *manifest.Store, name string, cs *manifest.Checksum, verified bool) error {
	e := store.FindBinary(name)
	if e == nil {
		return fmt.Errorf("binary entry %q not found", name)
	}
	e.Checksum = cs
	e.ChecksumVerified = verified
	return store.SaveBinary()
}
