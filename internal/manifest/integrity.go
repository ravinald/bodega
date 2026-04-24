package manifest

import (
	"crypto/md5" //nolint:gosec // MD5 used for manifest integrity, not cryptographic security.
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// md5Path returns the companion .md5 path for a manifest file.
func md5Path(manifestPath string) string {
	return manifestPath + ".md5"
}

// computeMD5 returns the lowercase hex MD5 digest of data.
func computeMD5(data []byte) string {
	sum := md5.Sum(data) //nolint:gosec
	return fmt.Sprintf("%x", sum)
}

// ReadMD5File reads the stored MD5 digest for a manifest.
// Returns empty string when the file does not exist.
func ReadMD5File(manifestPath string) (string, error) {
	p := md5Path(manifestPath)
	data, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read md5 file %s: %w", p, err)
	}
	return strings.TrimSpace(string(data)), nil
}

// WriteMD5File writes the MD5 digest of data to the companion file.
func WriteMD5File(manifestPath string, data []byte) error {
	digest := computeMD5(data)
	p := md5Path(manifestPath)
	if err := os.WriteFile(p, []byte(digest+"\n"), 0o644); err != nil {
		return fmt.Errorf("write md5 file %s: %w", p, err)
	}
	return nil
}

// VerifyMD5 checks that the stored MD5 matches the given data.
// Returns (true, nil) if they match, (false, nil) if they diverge,
// and (false, err) on I/O failure.
func VerifyMD5(manifestPath string, data []byte) (bool, error) {
	stored, err := ReadMD5File(manifestPath)
	if err != nil {
		return false, err
	}
	if stored == "" {
		// No companion file exists yet — treat as a first-time write; allow.
		return true, nil
	}
	actual := computeMD5(data)
	return stored == actual, nil
}

// ForceUpdateMD5 recomputes and writes the MD5 for an existing manifest file.
// This is the --break-glass-update-md5 escape hatch.
func ForceUpdateMD5(manifestDir, manifestType string) error {
	path := filepath.Join(manifestDir, manifestType+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read manifest %s: %w", path, err)
	}
	if err := WriteMD5File(path, data); err != nil {
		return err
	}
	fmt.Printf("Updated %s (digest: %s)\n", md5Path(path), computeMD5(data))
	return nil
}
