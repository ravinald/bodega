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

// SystemPepperPath is the pepper a privileged command writes, and the first
// path the server looks for one at.
const SystemPepperPath = "/etc/bodega/pepper"

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
	Shadowed []PepperCandidate

	// Created is true when this call generated the pepper at Path.
	Created bool
}

// PepperCandidate is a pepper path that exists and what reading it produced.
// A candidate that will not open is still a candidate: passing over it falls
// through to the next path in the search order, and a server hashing against a
// pepper the operator never minted against answers 401 to every token.
type PepperCandidate struct {
	Path string
	Err  error
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
	const consequence = "every token minted against it is refused with \"invalid token\", " +
		"which names the credential rather than this file"
	if !errors.Is(e.Err, fs.ErrPermission) {
		// A symlink cycle, a dangling target, a disk error: the path is broken
		// rather than closed, and no ownership change opens it. Naming one
		// here sends the operator to chmod a file that is not the problem.
		return fmt.Sprintf("pepper %s exists and cannot be read (%v): %s. Repair or remove it",
			e.Path, e.Err, consequence)
	}
	return fmt.Sprintf("pepper %s exists and this process (uid %d) cannot read it: %s. "+
		"Give the serving account read access "+
		"(chown root:<service-group> %s && chmod 0640 %s), or remove it",
		e.Path, os.Getuid(), consequence, e.Path, e.Path)
}

func (e *PepperUnreadableError) Unwrap() error { return e.Err }

// PepperHandoffError reports a pepper this process wrote and could not hand to
// the account the server runs as. Minting against it produces a token the
// server refuses with "invalid token", which names the credential rather than
// this file, so the mint fails here instead of printing one that validates
// nothing.
type PepperHandoffError struct {
	Path     string
	Identity ServiceIdentity
	Blocker  string
	Err      error
}

func (e *PepperHandoffError) Error() string {
	blocker := e.Blocker
	if blocker == "" {
		blocker = e.Path
	}
	msg := fmt.Sprintf("pepper %s is not readable by %q, the account %s runs the server as",
		e.Path, e.Identity.Name, e.Identity.Source)
	if blocker != e.Path {
		msg += fmt.Sprintf(" (%s refuses it)", blocker)
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg + ". Every token hashed against it would be refused with \"invalid token\". " +
		"Hand it over with: " + PepperRemedy("", blocker, e.Identity.Group)
}

// PepperRemedy names the commands that open blocker to group, each prefixed
// with run: "sudo " for a line an operator pastes later, empty for a command
// already running as root.
//
// What blocker is decides which commands they are. A directory needs search,
// and 0640 on it withholds the pepper exactly as before; the pepper itself
// needs read, and 0750 on a secret hands out the execute bit for nothing. A
// symlink resolves to one or the other, so neither can be assumed from the
// path the operator typed.
func PepperRemedy(run, blocker, group string) string {
	if fi, err := os.Stat(blocker); err == nil && fi.IsDir() {
		return fmt.Sprintf("%schgrp %s %s && %schmod 0750 %s", run, group, blocker, run, blocker)
	}
	return fmt.Sprintf("%schown root:%s %s && %schmod 0640 %s", run, group, blocker, run, blocker)
}

func (e *PepperHandoffError) Unwrap() error { return e.Err }

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
		default:
			// Permission, a symlink cycle, an I/O error: the path exists and
			// this process cannot read it. Returning here instead would
			// discard an already selected readable pepper because a candidate
			// further down the order is broken, and the server would serve
			// with no pepper at all.
			found = append(found, candidate{path: p, err: err})
		}
	}
	if len(found) == 0 {
		return PepperState{}, nil
	}
	st := PepperState{Path: found[0].path, Pepper: found[0].pepper}
	for _, c := range found[1:] {
		st.Shadowed = append(st.Shadowed, PepperCandidate{Path: c.path, Err: c.err})
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
		return PepperState{Path: p, Pepper: pepper, Created: true}, handToServiceAccount(p)
	}

	return PepperState{}, fmt.Errorf("could not write pepper to any path: %v", paths)
}

// handToServiceAccount gives a newly written pepper the group of the account
// the server runs as, and mode 0640.
//
// Group over the two alternatives: 0644 puts the key behind every token hash
// in reach of any shell on the box, and chowning the file to the service
// account lets a compromised server rewrite the secret the whole host's tokens
// are keyed on. Root keeps the write, the service group gets the read.
//
// Only a privileged process can hand a file to another account, so the chown
// is gated on euid and the result is verified either way. An unprivileged mint
// that already lands readable is fine; one that does not is an error, because
// the alternative is a token nothing will ever accept.
func handToServiceAccount(path string) error {
	id, err := ResolveServiceIdentity()
	switch {
	case errors.Is(err, ErrNoServiceAccount):
		return nil
	case err != nil:
		return err
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(path, 0, id.GID); err != nil {
			return &PepperHandoffError{Path: path, Identity: id, Err: err}
		}
		if err := os.Chmod(path, 0o640); err != nil {
			return &PepperHandoffError{Path: path, Identity: id, Err: err}
		}
	}
	return VerifyPepperHandoff(path)
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
