package audit

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// ServiceUserEnv names the account bodega serves as on a host with no systemd
// unit to read it from, and overrides the unit where there is one.
const ServiceUserEnv = "BODEGA_SERVICE_USER"

// ErrNoServiceAccount reports a host that names no separate account for the
// server: no BODEGA_SERVICE_USER, and no systemd unit carrying User=. Whoever
// writes the pepper there is whoever reads it, so there is nothing to hand
// over and 0600 is the right posture.
var ErrNoServiceAccount = errors.New("this host names no bodega service account")

// unitName and UnitSearchDirs reproduce systemd's own lookup, highest
// precedence first. Exported, like DefaultPepperPaths, so a test can point the
// resolver at a tree it built.
const unitName = "bodega.service"

var UnitSearchDirs = []string{
	"/etc/systemd/system",
	"/run/systemd/system",
	"/usr/local/lib/systemd/system",
	"/usr/lib/systemd/system",
	"/lib/systemd/system",
}

// ServiceIdentity is the account the server runs as. It is the account that
// has to be able to read the pepper every API token is hashed against, and it
// is not knowable from any file bodega owns: it lives in the unit.
type ServiceIdentity struct {
	// Name and Group are the account and the group carrying its read, as
	// resolved. Group is the unit's Group= where it names one, otherwise the
	// account's primary group.
	Name, Group string

	// UID and GID are their numeric ids.
	UID, GID int

	// GIDs is every group the account belongs to, GID included. A pepper
	// reachable through a supplementary group is reachable, and a check that
	// only compares the primary group calls a working install broken.
	GIDs []int

	// Source is where the account was declared, named in errors an operator
	// has to act on: a unit path, or ServiceUserEnv.
	Source string
}

// ResolveServiceIdentity reports the account the server runs as, or
// ErrNoServiceAccount where the host declares none.
func ResolveServiceIdentity() (ServiceIdentity, error) {
	name, group, source := declaredServiceAccount()
	if name == "" {
		return ServiceIdentity{}, ErrNoServiceAccount
	}
	u, err := user.Lookup(name)
	if err != nil {
		return ServiceIdentity{}, fmt.Errorf("%s runs the server as %q and this host has no such account: %w",
			source, name, err)
	}
	id := ServiceIdentity{Name: name, Source: source}
	if id.UID, err = strconv.Atoi(u.Uid); err != nil {
		return ServiceIdentity{}, fmt.Errorf("account %q has a non-numeric uid %q: %w", name, u.Uid, err)
	}

	gid := u.Gid
	if group != "" {
		g, err := user.LookupGroup(group)
		if err != nil {
			return ServiceIdentity{}, fmt.Errorf("%s runs the server in group %q and this host has no such group: %w",
				source, group, err)
		}
		gid = g.Gid
	}
	if id.GID, err = strconv.Atoi(gid); err != nil {
		return ServiceIdentity{}, fmt.Errorf("group %q has a non-numeric gid %q: %w", group, gid, err)
	}
	id.Group = group
	if id.Group == "" {
		if g, err := user.LookupGroupId(gid); err == nil {
			id.Group = g.Name
		} else {
			id.Group = gid
		}
	}

	id.GIDs = []int{id.GID}
	// Supplementary groups are best effort: os/user reads them from
	// /etc/group without cgo, and a host on LDAP returns nothing. Missing one
	// can only make this check stricter than the kernel, never looser.
	if extra, err := u.GroupIds(); err == nil {
		for _, s := range extra {
			if n, err := strconv.Atoi(s); err == nil && n != id.GID {
				id.GIDs = append(id.GIDs, n)
			}
		}
	}
	return id, nil
}

// VerifyPepperHandoff reports a pepper the account the server runs as cannot
// read, and reports nothing on a host that names no such account.
//
// A privileged command calls this before it mints: the alternative is a token
// the server answers "invalid token" to, which names the credential rather
// than the file, so the operator re-mints and meets the same 401. It covers a
// pepper written before this check existed as well as one written now, which
// is the state an upgrade lands in.
func VerifyPepperHandoff(path string) error {
	id, err := ResolveServiceIdentity()
	switch {
	case errors.Is(err, ErrNoServiceAccount):
		return nil
	case err != nil:
		return err
	}
	ok, blocker, err := id.CanRead(path)
	if ok {
		return nil
	}
	return &PepperHandoffError{Path: path, Identity: id, Blocker: blocker, Err: err}
}

// maxSymlinkHops bounds resolution where Linux does, so a symlink cycle is a
// reported refusal rather than a hang.
const maxSymlinkHops = 40

// CanRead reports whether id can open path for reading, and names the
// component that refuses it.
//
// It walks the path a component at a time the way the kernel does, because
// neither half alone is the answer. The directory half is not decoration:
// /etc/bodega at 0700 root:root withholds a pepper whose own mode grants it,
// and the operator has to chmod the directory rather than the file. Nor is a
// symlink transparent: os.Stat reports the target's mode and says nothing
// about the directories walked to reach it, so a root-only directory behind a
// symlinked config dir reads as success to a root process that can traverse it
// and the pepper lands where the service cannot open it. Resolving up front
// and checking only the target has the opposite blind spot, since the original
// path's own ancestors still have to grant search.
func (id ServiceIdentity) CanRead(path string) (ok bool, blocker string, err error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return false, path, err
	}

	cur := string(filepath.Separator)
	rest := pathComponents(abs)
	hops := 0
	for len(rest) > 0 {
		comp := rest[0]
		rest = rest[1:]
		if comp == "" || comp == "." {
			continue
		}
		// Search on every directory actually walked through, wherever a link
		// landed us, before anything inside it is looked up.
		if granted, err := id.grants(cur, 0o111); err != nil || !granted {
			return false, cur, err
		}
		if comp == ".." {
			cur = filepath.Dir(cur)
			continue
		}
		next := filepath.Join(cur, comp)
		fi, err := os.Lstat(next)
		if err != nil {
			return false, next, err
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			cur = next
			continue
		}
		if hops++; hops > maxSymlinkHops {
			return false, next, syscall.ELOOP
		}
		target, err := os.Readlink(next)
		if err != nil {
			return false, next, err
		}
		if filepath.IsAbs(target) {
			cur = string(filepath.Separator)
		}
		// A relative target resolves against the directory holding the link,
		// which is cur, so it stays put.
		rest = append(pathComponents(target), rest...)
	}
	// cur is what open(2) would land on, and read is what it needs there.
	if granted, err := id.grants(cur, 0o444); err != nil || !granted {
		return false, cur, err
	}
	return true, "", nil
}

// pathComponents splits a path into the names the walk consumes. Empty
// elements from a leading, trailing or doubled separator are left in and
// skipped by the caller, which is also what makes "/" a zero-component path.
func pathComponents(p string) []string {
	return strings.Split(strings.Trim(p, string(filepath.Separator)), string(filepath.Separator))
}

// grants reports whether id holds any of the bits in need on path.
//
// POSIX consults exactly one triple: match the owner and the group and other
// bits are never read, however wide they are. That is why a root:root 0640
// pepper refuses the service account on a host where root:root 0644 config.json
// does not, and why comparing the two files' grants to each other reports the
// pepper as fine.
func (id ServiceIdentity) grants(path string, need uint32) (bool, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	sys, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false, fmt.Errorf("%s: this platform reports no file ownership", path)
	}
	if id.UID == 0 {
		return true, nil
	}
	m := uint32(fi.Mode().Perm())
	switch {
	case int(sys.Uid) == id.UID:
		return m&need&0o700 != 0, nil
	case id.inGroup(int(sys.Gid)):
		return m&need&0o070 != 0, nil
	default:
		return m&need&0o007 != 0, nil
	}
}

func (id ServiceIdentity) inGroup(gid int) bool {
	for _, g := range id.GIDs {
		if g == gid {
			return true
		}
	}
	return false
}

// declaredServiceAccount reads the account out of the environment, then out
// of the unit and drop-ins systemd would load.
func declaredServiceAccount() (name, group, source string) {
	if v := strings.TrimSpace(os.Getenv(ServiceUserEnv)); v != "" {
		return v, "", ServiceUserEnv
	}
	for _, path := range unitFragments() {
		u, g := readUnitAccount(path)
		if u.set {
			name, source = u.value, path
		}
		if g.set {
			group = g.value
		}
	}
	if name == "" {
		return "", "", ""
	}
	return name, group, source
}

// unitFragments lists the files systemd reads for the unit, in the order it
// applies them: the unit itself, then its drop-ins.
//
// Two rules make this more than a walk of the search path, and getting either
// wrong selects an account the host does not serve as, which hands the pepper
// to the wrong group and leaves every minted token refused.
//
// A drop-in is selected by basename across the whole search path: an /etc
// bodega.service.d/10-account.conf masks the vendor file of the same name
// entirely, so a vendor User= systemd never reads must not reach the account.
// And what survives is applied in basename order regardless of the directory
// it came from, so a vendor 20-account.conf lands after an /etc
// 10-account.conf rather than before it.
func unitFragments() []string {
	var frags []string
	for _, dir := range UnitSearchDirs {
		path := filepath.Join(dir, unitName)
		if _, err := os.Stat(path); err == nil {
			// systemd stops at the first unit it finds, whether or not that
			// one names a User=. Falling through to a lower-precedence unit
			// that does names an account nothing on this host runs as.
			frags = append(frags, path)
			break
		}
	}
	if len(frags) == 0 {
		return nil
	}

	selected := make(map[string]string)
	for _, dir := range UnitSearchDirs {
		matches, _ := filepath.Glob(filepath.Join(dir, unitName+".d", "*.conf"))
		for _, m := range matches {
			if base := filepath.Base(m); selected[base] == "" {
				selected[base] = m
			}
		}
	}
	bases := make([]string, 0, len(selected))
	for base := range selected {
		bases = append(bases, base)
	}
	sort.Strings(bases)
	for _, base := range bases {
		frags = append(frags, selected[base])
	}
	return frags
}

// unitValue is an assignment as a fragment carried it, present or absent.
//
// systemd reads `Group=` with nothing after it as a reset to the default
// rather than as a group named "": the process runs in the effective user's
// primary group. Collapsing the two onto an empty string leaves the previous
// fragment's group standing, so a `systemctl edit` that clears Group= hands
// the pepper to a group the service is no longer in, and the check that
// follows the mint asks the same wrong identity and agrees.
type unitValue struct {
	value string
	set   bool
}

// readUnitAccount pulls User= and Group= out of a unit file's [Service]
// section. Last assignment wins, which is what systemd does with a key set
// twice. A file that names neither returns two unset values and changes
// nothing, which is how a drop-in carrying an unrelated setting behaves.
func readUnitAccount(path string) (name, group unitValue) {
	f, err := os.Open(path)
	if err != nil {
		return name, group
	}
	defer f.Close()

	section := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line
			continue
		}
		if section != "[Service]" {
			continue
		}
		k, v, found := strings.Cut(line, "=")
		switch {
		case !found:
		case strings.TrimSpace(k) == "User":
			name = unitValue{value: strings.TrimSpace(v), set: true}
		case strings.TrimSpace(k) == "Group":
			group = unitValue{value: strings.TrimSpace(v), set: true}
		}
	}
	return name, group
}
