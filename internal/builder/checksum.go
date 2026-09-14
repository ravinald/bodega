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

// checksumSourceBuild marks a digest this instance computed off bytes it
// fetched into its own build root.
//
// It is deliberately not "computed", which the proxy writes. Under the apt
// prefix that word is the only thing telling a .deb bodega mirrored from an
// archive from one bodega built, and server.aptMirroredPoolKeys drops every
// key carrying it out of the published index. A build row claiming it would
// withdraw the packages the build just produced.
const checksumSourceBuild = "manifest"

// updateVersionChecksum finds the VersionEntry in pm that matches targetVE
// (by Version or Ref), updates its Checksum and ChecksumVerified fields,
// saves the manifest, and pins the digest in the audit cache.
//
// Every per-type fetch funnels its digest through here, so the cache write
// lives here rather than at each of the seven call sites: the manifest field
// and the cache row record the same fact and would otherwise drift one type
// at a time.
func (c *Config) updateVersionChecksum(ctx context.Context, store *manifest.Store, typ, name string, targetVE manifest.VersionEntry, cs *manifest.Checksum, verified bool) error {
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
	var saved manifest.VersionEntry
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
			saved = *ve
			break
		}
	}
	if !found {
		return fmt.Errorf("version %q not found in %s/%s", targetKey, typ, name)
	}
	if err := store.SavePackage(ctx, pm); err != nil {
		return err
	}
	return c.pinChecksum(ctx, pm, saved, cs)
}

// pinChecksum records a version's digest in the audit cache that
// `bodega pkg checksum list` reads, and enforces an earlier one.
//
// The manifest field alone was never enough: it is written by the same fetch
// that computed it, so a fetch is checked against a value it just produced.
// The cache row is keyed by object key, which is the form the proxy verifies
// against on serve, so pinning it here makes one digest govern both paths.
//
// It never overwrites a digest already on record. A disagreement is reported
// rather than stored, and a row the proxy wrote keeps its own source: under
// the apt prefix, rewriting that word republishes an archive's bytes under
// bodega's own signature.
//
// pypi has no per-version object key — wheels upload as a directory covering a
// whole dependency closure — so ArtifactKeys returns ErrPypiNoObjectKey and
// there is nothing to key a row on. It is the one type this does not cover.
func (c *Config) pinChecksum(ctx context.Context, pm *manifest.PackageManifest, ve manifest.VersionEntry, cs *manifest.Checksum) error {
	if c.AuditDB == nil || cs == nil || cs.Value == "" {
		return nil
	}
	keys, err := manifest.ArtifactKeys(pm, ve)
	if err != nil || len(keys) == 0 {
		// No addressable object for this entry. Not a fetch failure: the
		// manifest still carries the digest, and `pkg verify` still covers
		// the manifest itself.
		return nil //nolint:nilerr // the sentinel errors are a fact about the type, not a failure
	}

	version := ve.Version
	if version == "" {
		version = ve.Ref
	}
	prior, err := c.AuditDB.GetChecksum(ctx, keys[0])
	if err != nil {
		return fmt.Errorf("read pinned checksum for %s: %w", keys[0], err)
	}
	if prior != nil && prior.Value != "" {
		if prior.Value != cs.Value {
			return fmt.Errorf("%s/%s@%s: %s mismatch against the pinned digest for %s: pinned=%s fetched=%s",
				pm.Type, pm.Name, version, cs.Algorithm, keys[0], prior.Value, cs.Value)
		}
		return nil
	}
	return c.AuditDB.StoreChecksum(ctx, keys[0], pm.Type, pm.Name, version, cs.Algorithm, cs.Value, checksumSourceBuild)
}

// findAndUpdateGitChecksum updates Checksum and ChecksumVerified on a git VersionEntry and saves.
func (c *Config) findAndUpdateGitChecksum(store *manifest.Store, name string, ve manifest.VersionEntry, cs *manifest.Checksum, verified bool) error {
	return c.updateVersionChecksum(context.Background(), store, manifest.TypeGit, name, ve, cs, verified)
}

// findAndUpdateGomodChecksum updates Checksum and ChecksumVerified on a gomod VersionEntry and saves.
func (c *Config) findAndUpdateGomodChecksum(store *manifest.Store, name string, ve manifest.VersionEntry, cs *manifest.Checksum, verified bool) error {
	return c.updateVersionChecksum(context.Background(), store, manifest.TypeGomod, name, ve, cs, verified)
}

// findAndUpdateHelmChecksum updates Checksum and ChecksumVerified on a helm VersionEntry and saves.
func (c *Config) findAndUpdateHelmChecksum(store *manifest.Store, name string, ve manifest.VersionEntry, cs *manifest.Checksum, verified bool) error {
	return c.updateVersionChecksum(context.Background(), store, manifest.TypeHelm, name, ve, cs, verified)
}

// findAndUpdateNpmChecksum updates Checksum and ChecksumVerified on an npm VersionEntry and saves.
func (c *Config) findAndUpdateNpmChecksum(store *manifest.Store, name string, ve manifest.VersionEntry, cs *manifest.Checksum, verified bool) error {
	return c.updateVersionChecksum(context.Background(), store, manifest.TypeNpm, name, ve, cs, verified)
}

// findAndUpdateBinaryChecksum updates Checksum and ChecksumVerified on a binary VersionEntry and saves.
func (c *Config) findAndUpdateBinaryChecksum(store *manifest.Store, name string, ve manifest.VersionEntry, cs *manifest.Checksum, verified bool) error {
	return c.updateVersionChecksum(context.Background(), store, manifest.TypeBinary, name, ve, cs, verified)
}

// findAndUpdateCargoChecksum updates Checksum and ChecksumVerified on a cargo VersionEntry and saves.
func (c *Config) findAndUpdateCargoChecksum(store *manifest.Store, name string, ve manifest.VersionEntry, cs *manifest.Checksum, verified bool) error {
	return c.updateVersionChecksum(context.Background(), store, manifest.TypeCargo, name, ve, cs, verified)
}
