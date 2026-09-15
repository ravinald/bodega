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

// unitName and unitSearchDirs reproduce systemd's own lookup, highest
// precedence first. A variable so a test can point it at a tree it built.
const unitName = "bodega.service"

var unitSearchDirs = []string{
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

// CanRead reports whether id can open path for reading, and names the first
// component that refuses it. The directory half is not decoration: /etc/bodega
// at 0700 root:root withholds a pepper whose own mode grants it, and the
// operator has to chmod the directory rather than the file.
func (id ServiceIdentity) CanRead(path string) (ok bool, blocker string, err error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return false, path, err
	}
	var chain []string
	for p := abs; ; p = filepath.Dir(p) {
		chain = append(chain, p)
		if p == filepath.Dir(p) {
			break
		}
	}
	// Root of the filesystem first: the outermost refusal is the one to report.
	for i := len(chain) - 1; i >= 0; i-- {
		need := uint32(0o111) // search, on every directory above the target
		if i == 0 {
			need = 0o444 // read, on the target itself
		}
		granted, err := id.grants(chain[i], need)
		if err != nil {
			return false, chain[i], err
		}
		if !granted {
			return false, chain[i], nil
		}
	}
	return true, "", nil
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

// declaredServiceAccount reads the account out of the environment, then out of
// the unit systemd would load, then out of the drop-ins that override it.
func declaredServiceAccount() (name, group, source string) {
	if v := strings.TrimSpace(os.Getenv(ServiceUserEnv)); v != "" {
		return v, "", ServiceUserEnv
	}
	for _, dir := range unitSearchDirs {
		u, g, ok := readUnitAccount(filepath.Join(dir, unitName))
		if !ok {
			continue
		}
		name, group, source = u, g, filepath.Join(dir, unitName)
		break
	}
	if name == "" {
		return "", "", ""
	}
	// Lowest precedence first, so `systemctl edit` under /etc lands last.
	for i := len(unitSearchDirs) - 1; i >= 0; i-- {
		conf, _ := filepath.Glob(filepath.Join(unitSearchDirs[i], unitName+".d", "*.conf"))
		sort.Strings(conf)
		for _, c := range conf {
			u, g, _ := readUnitAccount(c)
			if u != "" {
				name, source = u, c
			}
			if g != "" {
				group = g
			}
		}
	}
	return name, group, source
}

// readUnitAccount pulls User= and Group= out of a unit file's [Service]
// section. Last assignment wins, which is what systemd does with a key set
// twice; ok is false when the file names no User=, so the search moves on.
func readUnitAccount(path string) (name, group string, ok bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", false
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
			name = strings.TrimSpace(v)
		case strings.TrimSpace(k) == "Group":
			group = strings.TrimSpace(v)
		}
	}
	return name, group, name != ""
}
