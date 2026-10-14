package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// LoginCredential is the short-lived bodega token `bodega login` stored for
// one server, beside who it acts for and when it stops working.
type LoginCredential struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	Scopes    string    `json:"scopes,omitempty"`
	Subject   string    `json:"subject,omitempty"`
	Issuer    string    `json:"issuer,omitempty"`
}

// loginFile is the credentials file: one credential per server base URL.
type loginFile struct {
	Servers map[string]LoginCredential `json:"servers"`
}

// LoginCredentialsPath is where `bodega login` stores tokens: credentials.json
// under the user's config directory ($XDG_CONFIG_HOME/bodega on Linux,
// ~/Library/Application Support/bodega on macOS).
func LoginCredentialsPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate the user config directory: %w", err)
	}
	return filepath.Join(dir, "bodega", "credentials.json"), nil
}

// SaveLoginCredential records cred for serverURL, replacing any earlier one.
// The directory is 0700 and the file 0600, written through a temporary file
// and a rename so a reader never sees half a credential. A file already
// present with wider permissions is narrowed: it holds bearer tokens.
func SaveLoginCredential(path, serverURL string, cred LoginCredential) error {
	f, err := readLoginFile(path)
	if err != nil {
		return err
	}
	f.Servers[normalizeServerKey(serverURL)] = cred
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	body, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".credentials-*.json")
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod %s: %w", tmp.Name(), err)
	}
	if _, err := tmp.Write(append(body, '\n')); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", tmp.Name(), err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// LoadLoginCredential returns the credential stored for serverURL that is
// still in force at now, and false when there is none or it has expired.
func LoadLoginCredential(path, serverURL string, now time.Time) (LoginCredential, bool) {
	f, err := readLoginFile(path)
	if err != nil {
		return LoginCredential{}, false
	}
	cred, ok := f.Servers[normalizeServerKey(serverURL)]
	if !ok || cred.Token == "" || !cred.ExpiresAt.After(now) {
		return LoginCredential{}, false
	}
	return cred, true
}

func readLoginFile(path string) (loginFile, error) {
	f := loginFile{Servers: map[string]LoginCredential{}}
	body, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return f, fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(body, &f); err != nil {
		return f, fmt.Errorf("parse %s: %w", path, err)
	}
	if f.Servers == nil {
		f.Servers = map[string]LoginCredential{}
	}
	return f, nil
}

func normalizeServerKey(u string) string { return strings.TrimRight(u, "/") }

// ResolveTokenFor returns the bearer token a client authenticates to
// serverURL with: $BODEGA_TOKEN, then an unexpired token `bodega login`
// stored for that server, then the config file. The environment comes first
// so a token never has to be written to disk on a host being cataloged; a
// login comes before the file because it is the more recent, deliberate act.
func (c *Config) ResolveTokenFor(serverURL string) string {
	if v := os.Getenv(EnvToken); v != "" {
		return v
	}
	if path, err := LoginCredentialsPath(); err == nil && serverURL != "" {
		if cred, ok := LoadLoginCredential(path, serverURL, time.Now()); ok {
			return cred.Token
		}
	}
	return c.Token
}
