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
	"syscall"
)

// SystemPepperPath is the pepper a privileged command writes, beside the
// system config file it shares a posture with.
const SystemPepperPath = "/etc/bodega/pepper"

// PepperConfigSibling is the file a new pepper takes its group and mode from.
// bodega never learns the name of the account it runs as under systemd, so
// the posture is copied from the one file in the same directory the operator
// has already been told to hand to that account.
const PepperConfigSibling = "config.json"

// DefaultPepperPaths is the search order for the pepper file.
var DefaultPepperPaths = []string{
	SystemPepperPath,
	filepath.Join(userConfigDir(), "bodega", "pepper"),
}

// PepperState is the outcome of a search over the candidate paths.
type PepperState struct {
	// Path is the pepper in force: the first candidate that exists, whether
	// or not this process can read it. Empty when none exists.
	Path string

	// Pepper is its value. Empty when Path is unreadable or absent.
	Pepper string

	// Shadowed names every candidate that exists behind Path. Two peppers on
	// one host hash tokens differently, so the loser is reported rather than
	// quietly discarded.
	Shadowed []string

	// Created is true when this call generated the pepper at Path.
	Created bool
}

// PepperUnreadableError reports a pepper that exists and this process cannot
// read. It carries the path because the failure an operator meets downstream
// is a 401 saying "invalid token", which names the credential and not the
// file that actually refused.
type PepperUnreadableError struct {
	Path string
	Err  error
}

func (e *PepperUnreadableError) Error() string {
	return fmt.Sprintf("pepper %s exists and this process (uid %d) cannot read it: "+
		"every token minted against it is refused with \"invalid token\", which names the "+
		"credential rather than this file. Give the serving account read access "+
		"(chown root:<service-group> %s && chmod 0640 %s), or remove it",
		e.Path, os.Getuid(), e.Path, e.Path)
}

func (e *PepperUnreadableError) Unwrap() error { return e.Err }

// ResolvePepper walks the search order and reports what it found. The first
// candidate that exists wins, readable or not.
//
// Precedence by existence rather than by readability is what stops an
// unreadable /etc/bodega/pepper falling through to the next path. Falling
// through is silent and produces a server hashing against one pepper while
// the admin mints against another, with nothing in any log naming the file.
func ResolvePepper(paths []string) (PepperState, error) {
	type candidate struct {
		path   string
		pepper string
		err    error
	}
	var found []candidate
	for _, p := range paths {
		data, err := os.ReadFile(p)
		switch {
		case err == nil:
			pepper := strings.TrimSpace(string(data))
			if pepper == "" {
				// An empty file is not a pepper. Treating it as absent keeps
				// a truncated write from taking precedence over a good one.
				continue
			}
			found = append(found, candidate{path: p, pepper: pepper})
		case errors.Is(err, fs.ErrNotExist):
			continue
		case errors.Is(err, fs.ErrPermission):
			found = append(found, candidate{path: p, err: err})
		default:
			return PepperState{}, fmt.Errorf("read pepper %s: %w", p, err)
		}
	}
	if len(found) == 0 {
		return PepperState{}, nil
	}
	st := PepperState{Path: found[0].path, Pepper: found[0].pepper}
	for _, c := range found[1:] {
		st.Shadowed = append(st.Shadowed, c.path)
	}
	if found[0].err != nil {
		return st, &PepperUnreadableError{Path: found[0].path, Err: found[0].err}
	}
	return st, nil
}

// LoadOrCreatePepper resolves the pepper in force, generating one at the first
// writable path when none exists. It never creates a second pepper to work
// around one it cannot read: that error is returned.
func LoadOrCreatePepper(paths []string) (PepperState, error) {
	st, err := ResolvePepper(paths)
	if err != nil || st.Path != "" {
		return st, err
	}

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return PepperState{}, fmt.Errorf("generate pepper: %w", err)
	}
	pepper := hex.EncodeToString(b)

	for _, p := range paths {
		dir := filepath.Dir(p)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			continue
		}
		if err := os.WriteFile(p, []byte(pepper+"\n"), 0o600); err != nil {
			continue
		}
		adoptSiblingPosture(p)
		return PepperState{Path: p, Pepper: pepper, Created: true}, nil
	}

	return PepperState{}, fmt.Errorf("could not write pepper to any path: %v", paths)
}

// adoptSiblingPosture gives a newly written pepper the group and mode of the
// config file beside it, so an account that can read one can read the other.
//
// `sudo bodega token generate` otherwise leaves /etc/bodega/pepper at 0600
// root:root and the service, running as its own account, is refused by the
// kernel. Group plus 0640 was chosen over the two alternatives: 0644 makes the
// key behind every token hash readable by any shell on the box, and chowning
// to a literal "bodega" hardcodes an account name nothing requires, failing
// silently wherever the operator picked another.
//
// Best effort by design. A pepper that cannot be handed over is still written,
// and the startup refusal and `bodega doctor` both name it.
func adoptSiblingPosture(path string) {
	ref, err := os.Stat(filepath.Join(filepath.Dir(path), PepperConfigSibling))
	if err != nil {
		return
	}
	sys, ok := ref.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	if err := os.Chown(path, -1, int(sys.Gid)); err != nil {
		return
	}
	_ = os.Chmod(path, 0o640)
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
