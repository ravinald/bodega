package builder

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/ravinald/bodega/internal/manifest"
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

// ComputeBytesSHA256 returns the lowercase hex SHA-256 digest of a byte slice.
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

// updateVersionChecksum finds the VersionEntry in pm that matches targetVE
// (by Version or Ref), updates its Checksum and ChecksumVerified fields,
// and saves the manifest.
func updateVersionChecksum(ctx context.Context, store *manifest.Store, typ, name string, targetVE manifest.VersionEntry, cs *manifest.Checksum, verified bool) error {
	pm, err := store.GetPackage(ctx, typ, name)
	if err != nil {
		return fmt.Errorf("get package %s/%s: %w", typ, name, err)
	}
	if pm == nil {
		return fmt.Errorf("%s entry %q not found", typ, name)
	}

	targetKey := targetVE.Version
	if targetKey == "" {
		targetKey = targetVE.Ref
	}

	found := false
	for i := range pm.Versions {
		ve := &pm.Versions[i]
		veKey := ve.Version
		if veKey == "" {
			veKey = ve.Ref
		}
		if veKey == targetKey {
			ve.Checksum = cs
			ve.ChecksumVerified = verified
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("version %q not found in %s/%s", targetKey, typ, name)
	}
	return store.SavePackage(ctx, pm)
}

// findAndUpdateGitChecksum updates Checksum and ChecksumVerified on a git VersionEntry and saves.
func (c *Config) findAndUpdateGitChecksum(store *manifest.Store, name string, ve manifest.VersionEntry, cs *manifest.Checksum, verified bool) error {
	return updateVersionChecksum(context.Background(), store, manifest.TypeGit, name, ve, cs, verified)
}

// findAndUpdateGomodChecksum updates Checksum and ChecksumVerified on a gomod VersionEntry and saves.
func (c *Config) findAndUpdateGomodChecksum(store *manifest.Store, name string, ve manifest.VersionEntry, cs *manifest.Checksum, verified bool) error {
	return updateVersionChecksum(context.Background(), store, manifest.TypeGomod, name, ve, cs, verified)
}

// findAndUpdateHelmChecksum updates Checksum and ChecksumVerified on a helm VersionEntry and saves.
func (c *Config) findAndUpdateHelmChecksum(store *manifest.Store, name string, ve manifest.VersionEntry, cs *manifest.Checksum, verified bool) error {
	return updateVersionChecksum(context.Background(), store, manifest.TypeHelm, name, ve, cs, verified)
}

// findAndUpdateNpmChecksum updates Checksum and ChecksumVerified on an npm VersionEntry and saves.
func (c *Config) findAndUpdateNpmChecksum(store *manifest.Store, name string, ve manifest.VersionEntry, cs *manifest.Checksum, verified bool) error {
	return updateVersionChecksum(context.Background(), store, manifest.TypeNpm, name, ve, cs, verified)
}

// findAndUpdateBinaryChecksum updates Checksum and ChecksumVerified on a binary VersionEntry and saves.
func (c *Config) findAndUpdateBinaryChecksum(store *manifest.Store, name string, ve manifest.VersionEntry, cs *manifest.Checksum, verified bool) error {
	return updateVersionChecksum(context.Background(), store, manifest.TypeBinary, name, ve, cs, verified)
}

// findAndUpdateCargoChecksum updates Checksum and ChecksumVerified on a cargo VersionEntry and saves.
func (c *Config) findAndUpdateCargoChecksum(store *manifest.Store, name string, ve manifest.VersionEntry, cs *manifest.Checksum, verified bool) error {
	return updateVersionChecksum(context.Background(), store, manifest.TypeCargo, name, ve, cs, verified)
}
