package integration

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ravinald/bodega/internal/config"
)

// CredentialsEnv is the directory systemd's LoadCredential= populates.
const CredentialsEnv = "CREDENTIALS_DIRECTORY"

// secretFileSuffix marks the config key naming the file a secret is read
// from: api_token_file for api_token.
const secretFileSuffix = "_file"

// Redacted is what every surface prints in place of a secret value.
const Redacted = "[redacted]"

// Where a secret was found, for `bodega integration show`.
const (
	SourceCredentials = "$" + CredentialsEnv
	SourceEnv         = "environment"
	SourceFile        = "file"
)

// SecretEnv is the environment variable a secret is read from:
// BODEGA_<INSTANCE>_<KEY>, upper-cased, with '-' turned into '_'.
func SecretEnv(instance, key string) string {
	up := func(s string) string { return strings.ToUpper(strings.ReplaceAll(s, "-", "_")) }
	return "BODEGA_" + up(instance) + "_" + up(key)
}

// CredentialName is the file name a secret carries under
// $CREDENTIALS_DIRECTORY and in the directory `bodega integration secret`
// writes to.
func CredentialName(instance, key string) string { return instance + "." + key }

// Secret reads a secret field, in order: $CREDENTIALS_DIRECTORY/<instance>.<key>,
// which is where systemd's LoadCredential= puts it; BODEGA_<INSTANCE>_<KEY>;
// then the file the entry's <key>_file names. It returns the value and the
// source it came from. The value is never logged by anything in this package.
func (i *Instance) Secret(key string) (value, source string, err error) {
	// An unset, relative or root CREDENTIALS_DIRECTORY is skipped, as
	// internal/attestsign skips it: only systemd's absolute path is trusted.
	if dir := os.Getenv(CredentialsEnv); dir != "" && filepath.IsAbs(dir) && filepath.Clean(dir) != string(filepath.Separator) {
		b, err := os.ReadFile(filepath.Join(dir, CredentialName(i.Name, key)))
		switch {
		case err == nil:
			return strings.TrimSpace(string(b)), SourceCredentials, nil
		case !errors.Is(err, os.ErrNotExist):
			return "", "", fmt.Errorf("read %s/%s: %w", SourceCredentials, CredentialName(i.Name, key), err)
		}
	}
	if v := os.Getenv(SecretEnv(i.Name, key)); v != "" {
		return v, SourceEnv, nil
	}
	if p := i.secretFiles[key]; p != "" {
		info, err := os.Stat(p)
		if err != nil {
			return "", "", fmt.Errorf("read %s: %w", key+secretFileSuffix, err)
		}
		if mode := info.Mode().Perm(); mode&0o077 != 0 {
			return "", "", fmt.Errorf("%s %s is mode %#o and readable beyond its owner; run chmod 600 %s", key+secretFileSuffix, p, mode, p)
		}
		b, err := os.ReadFile(p) //nolint:gosec // operator-supplied path from the instance's own config
		if err != nil {
			return "", "", fmt.Errorf("read %s: %w", key+secretFileSuffix, err)
		}
		return strings.TrimSpace(string(b)), SourceFile + " " + p, nil
	}
	return "", "", fmt.Errorf("no secret found: run `bodega integration secret %s %s`, or set %s, or deliver %s with systemd's LoadCredential=",
		i.Name, key, SecretEnv(i.Name, key), CredentialName(i.Name, key))
}

// SecretDir is where `bodega integration secret` writes a credential when
// the entry names no <key>_file yet: credentials/ beside the config file in
// force, which a systemd unit can also hand over with LoadCredential=.
func SecretDir() string {
	return filepath.Join(filepath.Dir(config.ConfigPath()), "credentials")
}

// WriteSecret stores value as instance's secret key, mode 0600, and returns
// the path written. It writes to the entry's <key>_file when one is set, and
// otherwise to SecretDir; the caller records the path in the entry. It is the
// one write path for a secret: the CLI and the TUI both call it.
func WriteSecret(inst *Instance, key string, value io.Reader) (string, error) {
	f, ok := inst.Descriptor.Field(key)
	if !ok || !f.Secret {
		return "", fmt.Errorf("integrations.%s.%s: type %s has no secret field %q", inst.Name, key, inst.Descriptor.Type, key)
	}
	b, err := io.ReadAll(io.LimitReader(value, 64<<10))
	if err != nil {
		return "", err
	}
	secret := strings.TrimSpace(string(b))
	if secret == "" {
		return "", errors.New("no secret read from standard input")
	}
	path := inst.secretFiles[key]
	if path == "" {
		path = filepath.Join(SecretDir(), CredentialName(inst.Name, key))
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".secret-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return "", err
	}
	if _, err := tmp.WriteString(secret + "\n"); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return "", err
	}
	return path, nil
}

// SecretKey reports whether key names a secret in some form: a declared
// secret field, or a key ending the way client_setup.sh treats as one. It is
// the redaction rule for raw entries whose type is unknown.
func SecretKey(d *Descriptor, key string) bool {
	if d != nil {
		if f, ok := d.Field(key); ok {
			return f.Secret
		}
	}
	k := strings.ToLower(key)
	for _, suffix := range []string{"password", "passwd", "token", "secret", "_auth", "_key"} {
		if strings.HasSuffix(k, suffix) {
			return true
		}
	}
	return k == "apikey"
}

// Redact returns a copy of a raw entry with every secret value replaced, for
// show, --json and any log line or diff that prints an entry.
func Redact(raw config.Integration) config.Integration {
	var d *Descriptor
	if t, ok := raw["type"].(string); ok {
		d, _ = Lookup(t)
	}
	out := make(config.Integration, len(raw))
	for k, v := range raw {
		if SecretKey(d, k) {
			v = Redacted
		}
		out[k] = v
	}
	return out
}
