package audit

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

// worldTraversableDir is a scratch tree every uid can walk into. t.TempDir()
// sits under a per-user directory at 0700, so a synthetic account would be
// refused by the path rather than by the file under test and every case here
// would pass for the wrong reason.
func worldTraversableDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "bodega-svc")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("chmod %s: %v", dir, err)
	}
	return dir
}

// otherAccount is an identity that is nobody on this host: it matches no
// file's owner and belongs to no file's group, which is what the service
// account is from the perspective of a file root just wrote.
var otherAccount = ServiceIdentity{
	Name: "bodega", Group: "bodega",
	UID: 4242, GID: 4242, GIDs: []int{4242},
	Source: "/etc/systemd/system/bodega.service",
}

// TestCanReadConsultsOneTriple is the defect the shipped check had. POSIX
// picks the owner, group or other bits by the first match and never falls
// through, so a root:root 0644 config.json is readable by the service account
// and a root:root 0640 pepper beside it is not. Comparing the two files'
// grants to each other calls that pepper fine.
func TestCanReadConsultsOneTriple(t *testing.T) {
	dir := worldTraversableDir(t)
	cfg := filepath.Join(dir, "config.json")
	pepper := filepath.Join(dir, "pepper")
	if err := os.WriteFile(cfg, []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(pepper, []byte("5ca1ab1e\n"), 0o640); err != nil {
		t.Fatalf("write pepper: %v", err)
	}

	ok, _, err := otherAccount.CanRead(cfg)
	if err != nil || !ok {
		t.Fatalf("config.json at 0644 refused %q (err %v): the reproduction needs it readable", otherAccount.Name, err)
	}
	ok, blocker, err := otherAccount.CanRead(pepper)
	if err != nil {
		t.Fatalf("CanRead(%s): %v", pepper, err)
	}
	if ok {
		t.Fatalf("pepper at 0640 reported readable by %q, which owns it not and is in its group not", otherAccount.Name)
	}
	if blocker != pepper {
		t.Errorf("blocker %q, want the pepper itself", blocker)
	}
}

// A pepper handed over by group is readable, whether the group is the
// account's primary or a supplementary one.
func TestCanReadAcceptsAGroupGrant(t *testing.T) {
	dir := worldTraversableDir(t)
	pepper := filepath.Join(dir, "pepper")
	if err := os.WriteFile(pepper, []byte("5ca1ab1e\n"), 0o640); err != nil {
		t.Fatalf("write pepper: %v", err)
	}
	fi, err := os.Stat(pepper)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	gid := int(fi.Sys().(*syscall.Stat_t).Gid)

	for _, tc := range []struct {
		name string
		gids []int
	}{
		{"primary group", []int{gid}},
		{"supplementary group", []int{4242, gid}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := otherAccount
			id.GID, id.GIDs = tc.gids[0], tc.gids
			ok, blocker, err := id.CanRead(pepper)
			if err != nil || !ok {
				t.Fatalf("CanRead = %v (blocker %q, err %v), want readable through gid %d", ok, blocker, err, gid)
			}
		})
	}
}

// The directory half. /etc/bodega at 0700 root:root withholds a pepper whose
// own mode hands it over, and the chown the operator needs is on the
// directory, so the refusal has to name it.
func TestCanReadNamesTheDirectoryThatRefuses(t *testing.T) {
	dir := worldTraversableDir(t)
	etc := filepath.Join(dir, "bodega")
	if err := os.Mkdir(etc, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	pepper := filepath.Join(etc, "pepper")
	if err := os.WriteFile(pepper, []byte("5ca1ab1e\n"), 0o644); err != nil {
		t.Fatalf("write pepper: %v", err)
	}

	ok, blocker, err := otherAccount.CanRead(pepper)
	if err != nil {
		t.Fatalf("CanRead: %v", err)
	}
	if ok {
		t.Fatal("a 0644 pepper inside a 0700 directory reported readable")
	}
	if blocker != etc {
		t.Errorf("blocker %q, want the directory %q", blocker, etc)
	}
}

// writeUnit lands a unit file the way the shipped docs/bodega.service does,
// with the keys that matter buried among sections that carry none.
func writeUnit(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestDeclaredServiceAccount(t *testing.T) {
	const unit = `[Unit]
Description=bodega
# User=decoy — a comment is not an assignment
User=wrong-section

[Service]
Type=notify
User=bodega
Group=bodega
ExecStart=/usr/local/bin/bodega serve

[Install]
WantedBy=multi-user.target
`
	t.Run("the unit's [Service] section", func(t *testing.T) {
		dir := t.TempDir()
		writeUnit(t, filepath.Join(dir, "etc", unitName), unit)
		swapUnitDirs(t, filepath.Join(dir, "etc"), filepath.Join(dir, "lib"))

		name, group, source := declaredServiceAccount()
		if name != "bodega" || group != "bodega" {
			t.Fatalf("got %q/%q, want bodega/bodega", name, group)
		}
		if source != filepath.Join(dir, "etc", unitName) {
			t.Errorf("source %q does not name the unit it came from", source)
		}
	})

	t.Run("a drop-in overrides the unit", func(t *testing.T) {
		dir := t.TempDir()
		writeUnit(t, filepath.Join(dir, "lib", unitName), unit)
		writeUnit(t, filepath.Join(dir, "etc", unitName+".d", "10-user.conf"),
			"[Service]\nUser=repo\nGroup=repo\n")
		swapUnitDirs(t, filepath.Join(dir, "etc"), filepath.Join(dir, "lib"))

		name, group, _ := declaredServiceAccount()
		if name != "repo" || group != "repo" {
			t.Fatalf("got %q/%q, want repo/repo: `systemctl edit` is how an operator moves the account", name, group)
		}
	})

	// The review's second reproduction. `systemctl edit` that clears Group=
	// writes the key with nothing after it, which systemd reads as a reset to
	// the effective user's primary group rather than as a group named "". A
	// parse that cannot tell an empty assignment from a missing one keeps the
	// unit's original group and hands the pepper to it.
	t.Run("an empty Group= clears the unit's group", func(t *testing.T) {
		dir := t.TempDir()
		writeUnit(t, filepath.Join(dir, "lib", unitName), unit)
		writeUnit(t, filepath.Join(dir, "etc", unitName+".d", "10-account.conf"),
			"[Service]\nUser=daemon\nGroup=\n")
		swapUnitDirs(t, filepath.Join(dir, "etc"), filepath.Join(dir, "lib"))

		name, group, _ := declaredServiceAccount()
		if name != "daemon" || group != "" {
			t.Fatalf("got %q/%q, want daemon and no group: systemd runs a reset Group= as "+
				"daemon's primary group, not as the unit's own %q", name, group, "bodega")
		}
	})

	// The other half of the same distinction: a drop-in that never mentions
	// Group= leaves the unit's standing, so treating both as empty would move
	// the pepper off a group the operator did name.
	t.Run("an absent Group= leaves the unit's group", func(t *testing.T) {
		dir := t.TempDir()
		writeUnit(t, filepath.Join(dir, "lib", unitName), unit)
		writeUnit(t, filepath.Join(dir, "etc", unitName+".d", "10-account.conf"),
			"[Service]\nUser=daemon\n")
		swapUnitDirs(t, filepath.Join(dir, "etc"), filepath.Join(dir, "lib"))

		name, group, _ := declaredServiceAccount()
		if name != "daemon" || group != "bodega" {
			t.Fatalf("got %q/%q, want daemon/bodega: the drop-in names no Group=", name, group)
		}
	})

	// User= resets the same way, and there it means root: no separate account,
	// so whoever writes the pepper reads it and 0600 is the right posture.
	t.Run("an empty User= clears the unit's account", func(t *testing.T) {
		dir := t.TempDir()
		writeUnit(t, filepath.Join(dir, "lib", unitName), unit)
		writeUnit(t, filepath.Join(dir, "etc", unitName+".d", "10-account.conf"),
			"[Service]\nUser=\n")
		swapUnitDirs(t, filepath.Join(dir, "etc"), filepath.Join(dir, "lib"))

		if name, _, _ := declaredServiceAccount(); name != "" {
			t.Fatalf("got %q, want no account: a reset User= runs the server as root", name)
		}
	})

	// The review's reproduction. systemd selects drop-ins by basename across
	// the whole search path, so an /etc file masks the vendor file of the same
	// name and the vendor User= is never read. Applying both hands the pepper
	// to an account the host does not serve as, and doctor then reports that
	// same wrong account as able to read it.
	t.Run("an /etc drop-in masks the vendor file of the same name", func(t *testing.T) {
		dir := t.TempDir()
		writeUnit(t, filepath.Join(dir, "lib", unitName), unit)
		writeUnit(t, filepath.Join(dir, "lib", unitName+".d", "10-account.conf"),
			"[Service]\nUser=daemon\nGroup=daemon\n")
		writeUnit(t, filepath.Join(dir, "etc", unitName+".d", "10-account.conf"),
			"[Service]\nRestart=always\n")
		swapUnitDirs(t, filepath.Join(dir, "etc"), filepath.Join(dir, "lib"))

		name, group, _ := declaredServiceAccount()
		if name != "bodega" || group != "bodega" {
			t.Fatalf("got %q/%q, want bodega/bodega: systemd never reads the vendor drop-in the "+
				"/etc file of the same name masks, and runs the server as the unit's own User=", name, group)
		}
	})

	// Drop-ins are ordered by basename regardless of the directory they came
	// from, so a vendor 20- file is applied after an /etc 10- file. Walking
	// the directories in precedence order reverses that pair.
	t.Run("drop-ins apply in basename order across directories", func(t *testing.T) {
		dir := t.TempDir()
		writeUnit(t, filepath.Join(dir, "lib", unitName), unit)
		writeUnit(t, filepath.Join(dir, "etc", unitName+".d", "10-account.conf"),
			"[Service]\nUser=first\nGroup=first\n")
		writeUnit(t, filepath.Join(dir, "lib", unitName+".d", "20-account.conf"),
			"[Service]\nUser=second\nGroup=second\n")
		swapUnitDirs(t, filepath.Join(dir, "etc"), filepath.Join(dir, "lib"))

		name, group, _ := declaredServiceAccount()
		if name != "second" || group != "second" {
			t.Fatalf("got %q/%q, want second/second: 20-account.conf sorts last wherever it lives", name, group)
		}
	})

	// systemd loads the first unit file on the search path and stops. One at
	// /etc naming no User= runs the server as root; falling through to a
	// vendor unit that names one picks an account nothing here serves as.
	t.Run("the first unit file on the path wins, User= or not", func(t *testing.T) {
		dir := t.TempDir()
		writeUnit(t, filepath.Join(dir, "etc", unitName),
			"[Service]\nType=notify\nExecStart=/usr/local/bin/bodega serve\n")
		writeUnit(t, filepath.Join(dir, "lib", unitName), unit)
		swapUnitDirs(t, filepath.Join(dir, "etc"), filepath.Join(dir, "lib"))

		if name, _, _ := declaredServiceAccount(); name != "" {
			t.Fatalf("got %q, want no account: the unit in force names no User=", name)
		}
	})

	t.Run("no unit and no environment", func(t *testing.T) {
		dir := t.TempDir()
		swapUnitDirs(t, filepath.Join(dir, "etc"))
		if _, err := ResolveServiceIdentity(); !errors.Is(err, ErrNoServiceAccount) {
			t.Fatalf("err = %v, want ErrNoServiceAccount", err)
		}
	})

	t.Run("the environment overrides the unit", func(t *testing.T) {
		dir := t.TempDir()
		writeUnit(t, filepath.Join(dir, "etc", unitName), unit)
		swapUnitDirs(t, filepath.Join(dir, "etc"))
		t.Setenv(ServiceUserEnv, "repo")

		name, _, source := declaredServiceAccount()
		if name != "repo" || source != ServiceUserEnv {
			t.Fatalf("got %q from %q, want repo from %s", name, source, ServiceUserEnv)
		}
	})
}

// An account the unit names and the host does not have is an error, not an
// absence: the service cannot start either, and reporting "no service account"
// would send the operator looking at the pepper instead of at useradd.
func TestResolveServiceIdentityReportsAMissingAccount(t *testing.T) {
	t.Setenv(ServiceUserEnv, "no-such-account-"+strconv.Itoa(os.Getpid()))
	_, err := ResolveServiceIdentity()
	if err == nil || errors.Is(err, ErrNoServiceAccount) {
		t.Fatalf("err = %v, want a lookup failure naming the account", err)
	}
}

func TestResolveServiceIdentityFillsTheGroupSet(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skipf("no account for this process: %v", err)
	}
	t.Setenv(ServiceUserEnv, me.Username)

	id, err := ResolveServiceIdentity()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if id.UID != os.Getuid() {
		t.Errorf("uid %d, want %d", id.UID, os.Getuid())
	}
	if !id.inGroup(id.GID) {
		t.Errorf("GIDs %v does not carry the primary gid %d", id.GIDs, id.GID)
	}
	if id.Group == "" {
		t.Error("Group is empty; the chown in every remediation line names it")
	}
}

// A cleared Group= has to reach the numeric gid, not just the parsed string:
// the chown in the handoff and in every remediation line is keyed on it, and
// the group the unit named before the edit is one the service is no longer in.
func TestResolveServiceIdentityFollowsAClearedGroup(t *testing.T) {
	serving, stale := twoServiceAccounts(t)
	units := t.TempDir()
	writeUnit(t, filepath.Join(units, "lib", unitName),
		"[Service]\nType=notify\nUser="+serving.Username+"\nGroup="+groupNameOf(t, stale)+"\n")
	writeUnit(t, filepath.Join(units, "etc", unitName+".d", "10-account.conf"),
		"[Service]\nGroup=\n")
	swapUnitDirs(t, filepath.Join(units, "etc"), filepath.Join(units, "lib"))

	id, err := ResolveServiceIdentity()
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if want := gidOf(t, serving); id.GID != want {
		t.Fatalf("resolved gid %d (%q), want %d (%q): an empty Group= selects %s's primary group",
			id.GID, id.Group, want, groupNameOf(t, serving), serving.Username)
	}
}

func swapUnitDirs(t *testing.T, dirs ...string) {
	t.Helper()
	prev := UnitSearchDirs
	UnitSearchDirs = dirs
	t.Cleanup(func() { UnitSearchDirs = prev })
}
