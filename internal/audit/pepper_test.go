package audit

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
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

// TestUnreadablePepperRefusesRatherThanFallingThrough pins requirement 2. The
// two-account validation is TestTokenMintedAsRootValidatesAgainstAnotherAccount
// in cmd/bodega, which needs two real accounts; this one measures what the
// serve side does when the pepper the token was minted against is closed to
// it. Falling through to the second pepper produces a value that validates
// nothing and reports nothing: the operator meets a 401 saying "invalid token"
// and re-mints into the same wall.
func TestUnreadablePepperRefusesRatherThanFallingThrough(t *testing.T) {
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

// TestCreatedPepperIsHandedToTheServiceAccount pins requirement 1 as the
// contract it is, which holds at either privilege level: when
// LoadOrCreatePepper returns nil the service account can read what it wrote,
// and when it cannot the call is an error rather than a pepper every future
// token dies against.
//
// Unprivileged, the chown is not available and the error is the outcome; as
// root the chown lands and readability is. The shipped tree returns nil in
// both cases, having copied config.json's gid without ever asking whether the
// service account could read the result.
func TestCreatedPepperIsHandedToTheServiceAccount(t *testing.T) {
	dir := worldTraversableDir(t)
	path := filepath.Join(dir, "pepper")
	t.Setenv(ServiceUserEnv, secondAccount(t))

	st, err := LoadOrCreatePepper([]string{path})
	if st.Path != path || !st.Created {
		t.Fatalf("created=%v path=%s, want true and %s", st.Created, st.Path, path)
	}
	id, idErr := ResolveServiceIdentity()
	if idErr != nil {
		t.Fatalf("resolve service identity: %v", idErr)
	}
	readable, blocker, canErr := id.CanRead(path)
	if canErr != nil {
		t.Fatalf("CanRead(%s): %v", path, canErr)
	}

	switch {
	case readable && err != nil:
		t.Fatalf("pepper is readable by %q and the mint still failed: %v", id.Name, err)
	case readable:
		if mode := modeOf(t, path); mode != 0o640 {
			t.Errorf("pepper mode %04o, want 0640: 0644 puts the key behind every token hash on the box "+
				"in reach of any shell", mode)
		}
	case err == nil:
		t.Fatalf("%s refuses %q and LoadOrCreatePepper returned nil: every token minted against it "+
			"would be answered \"invalid token\"", blocker, id.Name)
	default:
		var handoff *PepperHandoffError
		if !errors.As(err, &handoff) {
			t.Fatalf("err = %v, want a *PepperHandoffError naming %s", err, path)
		}
		if handoff.Path != path || handoff.Identity.Name != id.Name {
			t.Errorf("handoff names %s/%q, want %s/%q", handoff.Path, handoff.Identity.Name, path, id.Name)
		}
	}
}

// TestCreatedPepperFollowsTheUnitSystemdWouldLoad drives the handoff through
// the unit resolver rather than BODEGA_SERVICE_USER, because which account
// that resolution selects is the defect the review sent back: a vendor drop-in
// masked by an /etc file of the same name named a second account, the pepper
// went to that account's group, and the server kept running as the unit's own
// User= with every minted token refused.
func TestCreatedPepperFollowsTheUnitSystemdWouldLoad(t *testing.T) {
	serving, masked := twoServiceAccounts(t)
	units := t.TempDir()
	writeUnit(t, filepath.Join(units, "lib", unitName),
		"[Service]\nType=notify\nUser="+serving.Username+"\n")
	writeUnit(t, filepath.Join(units, "lib", unitName+".d", "10-account.conf"),
		"[Service]\nUser="+masked.Username+"\n")
	writeUnit(t, filepath.Join(units, "etc", unitName+".d", "10-account.conf"),
		"[Service]\nRestart=always\n")
	swapUnitDirs(t, filepath.Join(units, "etc"), filepath.Join(units, "lib"))

	dir := worldTraversableDir(t)
	path := filepath.Join(dir, "pepper")
	st, err := LoadOrCreatePepper([]string{path})
	if st.Path != path || !st.Created {
		t.Fatalf("created=%v path=%s, want true and %s", st.Created, st.Path, path)
	}
	servingGID, maskedGID := gidOf(t, serving), gidOf(t, masked)

	if os.Geteuid() == 0 {
		if err != nil {
			t.Fatalf("mint: %v", err)
		}
		gid := int(fiOf(t, path).Sys().(*syscall.Stat_t).Gid)
		switch gid {
		case maskedGID:
			t.Fatalf("pepper handed to gid %d (%s), the account in the drop-in systemd masks: "+
				"%s serves and cannot read it", gid, masked.Username, serving.Username)
		case servingGID:
		default:
			t.Fatalf("pepper gid %d, want %d (%s)", gid, servingGID, serving.Username)
		}
		return
	}

	// Unprivileged there is no chown to make, so the refusal is the outcome
	// and the account it names is what this case measures.
	var handoff *PepperHandoffError
	if !errors.As(err, &handoff) {
		t.Fatalf("err = %v, want a *PepperHandoffError: %s cannot read a 0600 pepper this process owns",
			err, serving.Username)
	}
	if handoff.Identity.Name != serving.Username {
		t.Fatalf("handoff names %q, want %q: the drop-in naming %q is masked and systemd never reads it",
			handoff.Identity.Name, serving.Username, masked.Username)
	}
}

// A pepper written before this check existed reaches `token generate` through
// the load path, not the create path, so the mint verifies what it loaded too.
// This is the state an upgrade lands in: /etc/bodega/pepper already on disk,
// 0600 root:root, and the tokens keyed on it already dead.
func TestVerifyPepperHandoffCatchesAPepperItDidNotWrite(t *testing.T) {
	dir := worldTraversableDir(t)
	path := filepath.Join(dir, "pepper")
	writePepper(t, path, "5ca1ab1e")
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Setenv(ServiceUserEnv, secondAccount(t))

	if os.Geteuid() == 0 {
		// Root owns it and root reads everything, so the file has to be
		// handed to a third party for the refusal to be about the account.
		if err := os.Chown(path, 0, 0); err != nil {
			t.Fatalf("chown: %v", err)
		}
	}
	err := VerifyPepperHandoff(path)
	var handoff *PepperHandoffError
	if !errors.As(err, &handoff) {
		t.Fatalf("err = %v, want a *PepperHandoffError: a 0600 pepper is readable by its owner alone", err)
	}
	if !strings.Contains(handoff.Error(), "chown root:") {
		t.Errorf("error %q carries no command to run", handoff.Error())
	}
}

// A host with no unit and no environment override runs the server as whoever
// ran the command. There is no second account to hand anything to, and a
// refusal there would break every single-account install.
func TestPepperHandoffIsSilentWithNoServiceAccount(t *testing.T) {
	dir := worldTraversableDir(t)
	swapUnitDirs(t, filepath.Join(dir, "no-systemd-here"))

	path := filepath.Join(dir, "pepper")
	st, err := LoadOrCreatePepper([]string{path})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if mode := modeOf(t, st.Path); mode != 0o600 {
		t.Errorf("pepper mode %04o, want 0600: nothing on this host needs it wider", mode)
	}
}

// secondAccount names an account this process is not. Every case that needs
// one needs it to exist, because ResolveServiceIdentity refuses a name the
// host cannot look up.
func secondAccount(t *testing.T) string {
	t.Helper()
	for _, name := range []string{"nobody", "daemon", "bin", "games"} {
		u, err := user.Lookup(name)
		if err != nil {
			continue
		}
		if uid, err := strconv.Atoi(u.Uid); err == nil && uid != os.Getuid() {
			return name
		}
	}
	t.Skip("this host has no second account to hand a pepper to")
	return ""
}

// twoServiceAccounts names two accounts this process is not, with distinct
// groups: one the unit runs the server as, one a masked drop-in names.
func twoServiceAccounts(t *testing.T) (serving, masked *user.User) {
	t.Helper()
	var found []*user.User
	for _, name := range []string{"daemon", "bin", "www", "games", "sys", "nobody"} {
		u, err := user.Lookup(name)
		if err != nil {
			continue
		}
		uid, err := strconv.Atoi(u.Uid)
		if err != nil || uid == os.Getuid() {
			continue
		}
		if len(found) == 1 && u.Gid == found[0].Gid {
			continue
		}
		if found = append(found, u); len(found) == 2 {
			return found[0], found[1]
		}
	}
	t.Skip("this host has fewer than two accounts to model a masked drop-in with")
	return nil, nil
}

func gidOf(t *testing.T, u *user.User) int {
	t.Helper()
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		t.Fatalf("gid of %s: %v", u.Username, err)
	}
	return gid
}

func fiOf(t *testing.T, path string) os.FileInfo {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi
}

func modeOf(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.Mode().Perm()
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
