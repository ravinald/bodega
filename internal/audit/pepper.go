package audit

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// DefaultPepperPaths is the search order for the pepper file.
var DefaultPepperPaths = []string{
	"/etc/bodega/pepper",
	filepath.Join(userConfigDir(), "bodega", "pepper"),
}

// LoadOrCreatePepper reads the pepper from the first path that exists. If no
// path contains a pepper, a new one is generated and written to the first
// writable path. Returns the pepper hex string.
func LoadOrCreatePepper(paths []string) (string, error) {
	// Try to read an existing pepper.
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err == nil {
			pepper := strings.TrimSpace(string(data))
			if pepper != "" {
				return pepper, nil
			}
		}
		if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, fs.ErrPermission) {
			return "", fmt.Errorf("read pepper %s: %w", p, err)
		}
	}

	// Generate a new pepper.
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate pepper: %w", err)
	}
	pepper := hex.EncodeToString(b)

	// Write to the first writable path.
	for _, p := range paths {
		dir := filepath.Dir(p)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			continue
		}
		if err := os.WriteFile(p, []byte(pepper+"\n"), 0o600); err != nil {
			continue
		}
		return pepper, nil
	}

	return "", fmt.Errorf("could not write pepper to any path: %v", paths)
}

// LoadPepper reads the pepper from the first path that exists. Returns an
// error if no pepper file is found. Used by the server (read-only, never
// creates).
func LoadPepper(paths []string) (string, error) {
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err == nil {
			pepper := strings.TrimSpace(string(data))
			if pepper != "" {
				return pepper, nil
			}
		}
		if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, fs.ErrPermission) {
			return "", fmt.Errorf("read pepper %s: %w", p, err)
		}
	}
	return "", fmt.Errorf("no pepper file found (searched: %v)", paths)
}

// HashToken computes HMAC-SHA256(token, pepper) and returns the hex-encoded result.
// This is the canonical way to hash tokens for storage and verification.
func HashToken(token, pepper string) string {
	mac := hmac.New(sha256.New, []byte(pepper))
	mac.Write([]byte(token))
	return hex.EncodeToString(mac.Sum(nil))
}

func userConfigDir() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return dir
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config")
}
