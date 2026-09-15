package audit

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// writePepper lands a pepper the way a privileged command does: mode 0600,
// owned by whoever is running.
func writePepper(t *testing.T, path, value string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestTokenMintedByPrivilegedProcessValidatesForServiceAccount is the whole of
// QUICKSTART §12 in one function: root mints a token against the system
// pepper, and the account the server runs as loads a pepper from the same
// search order.
//
// The two accounts are modelled by readability, which is the only thing that
// differs between them here. Falling through to the second pepper produces a
// value that validates nothing and reports nothing, which is the defect: the
// operator meets a 401 saying "invalid token" and re-mints into the same wall.
func TestTokenMintedByPrivilegedProcessValidatesForServiceAccount(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every file, so the two-account split cannot be modelled in-process")
	}
	dir := t.TempDir()
	system := filepath.Join(dir, "etc", "pepper")
	xdg := filepath.Join(dir, "state", ".config", "bodega", "pepper")
	paths := []string{system, xdg}

	writePepper(t, system, "5ca1ab1e")
	writePepper(t, xdg, "0ddba11")

	// The mint, as root: the system pepper wins and the hash is keyed on it.
	minted, err := LoadOrCreatePepper(paths)
	if err != nil {
		t.Fatalf("mint-side load: %v", err)
	}
	if minted.Path != system {
		t.Fatalf("mint keyed on %s, want %s", minted.Path, system)
	}
	const token = "bodega_ak_" + "6465616462656566"
	stored := HashToken(token, minted.Pepper)

	// The serve side, as an account that cannot read what root wrote.
	if err := os.Chmod(system, 0o000); err != nil {
		t.Fatalf("chmod %s: %v", system, err)
	}
	t.Cleanup(func() { _ = os.Chmod(system, 0o600) })

	served, err := ResolvePepper(paths)
	if err != nil {
		var unreadable *PepperUnreadableError
		if !errors.As(err, &unreadable) {
			t.Fatalf("serve-side load: %v", err)
		}
		if unreadable.Path != system {
			t.Fatalf("refusal names %s, want the pepper the token was minted against (%s)", unreadable.Path, system)
		}
		return
	}
	if HashToken(token, served.Pepper) != stored {
		t.Fatalf("serve side loaded %s, which validates no token minted against %s, "+
			"and returned no error naming either", served.Path, system)
	}
}

// TestCreatedPepperAdoptsConfigPosture pins requirement 1: a pepper a
// privileged command writes is readable by the account that reads the config
// file beside it, and by nobody wider.
func TestCreatedPepperAdoptsConfigPosture(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pepper")
	cfg := filepath.Join(dir, PepperConfigSibling)
	if err := os.WriteFile(cfg, []byte("{}\n"), 0o640); err != nil {
		t.Fatalf("write %s: %v", cfg, err)
	}

	st, err := LoadOrCreatePepper([]string{path})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !st.Created || st.Path != path {
		t.Fatalf("created=%v path=%s, want true and %s", st.Created, st.Path, path)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := fi.Mode().Perm(); got != 0o640 {
		t.Fatalf("pepper mode %04o, want 0640: the group that reads the config cannot read it", got)
	}
	ref, err := os.Stat(cfg)
	if err != nil {
		t.Fatalf("stat %s: %v", cfg, err)
	}
	pepperGid := fi.Sys().(*syscall.Stat_t).Gid
	refGid := ref.Sys().(*syscall.Stat_t).Gid
	if pepperGid != refGid {
		t.Fatalf("pepper gid %d, config gid %d: the pepper does not follow the config's group", pepperGid, refGid)
	}
}

// TestSecondPepperIsReportedNotPreferred pins requirement 3: the first path
// that exists wins, and the loser is named rather than dropped.
func TestSecondPepperIsReportedNotPreferred(t *testing.T) {
	dir := t.TempDir()
	system := filepath.Join(dir, "etc", "pepper")
	xdg := filepath.Join(dir, "state", "pepper")
	writePepper(t, system, "5ca1ab1e")
	writePepper(t, xdg, "0ddba11")

	st, err := ResolvePepper([]string{system, xdg})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if st.Path != system || st.Pepper != "5ca1ab1e" {
		t.Fatalf("in force %s (%s), want %s", st.Path, st.Pepper, system)
	}
	if len(st.Shadowed) != 1 || st.Shadowed[0] != xdg {
		t.Fatalf("shadowed %v, want [%s]", st.Shadowed, xdg)
	}
}

// TestEmptyPepperIsNotAPepper keeps a truncated write from taking precedence
// over a good pepper further down the search order.
func TestEmptyPepperIsNotAPepper(t *testing.T) {
	dir := t.TempDir()
	system := filepath.Join(dir, "etc", "pepper")
	xdg := filepath.Join(dir, "state", "pepper")
	writePepper(t, system, "")
	writePepper(t, xdg, "0ddba11")

	st, err := ResolvePepper([]string{system, xdg})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if st.Path != xdg {
		t.Fatalf("in force %s, want %s", st.Path, xdg)
	}
	if len(st.Shadowed) != 0 {
		t.Fatalf("shadowed %v, want none", st.Shadowed)
	}
}
