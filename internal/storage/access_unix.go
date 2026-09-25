//go:build linux || darwin || freebsd

package storage

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// access is everything about a stored object that decides who can reach it:
// the permission bits, the owning uid and gid, and the extended attributes,
// which is where a POSIX ACL and a security label live.
//
// Publication replaces the inode, so a rename carries none of it. The mode
// alone does not answer the question either: a file at 0644 can deny one named
// user through its access ACL, and a replacement that kept the 0644 and
// dropped the ACL hands that user the artifact. A group is the same boundary
// in the other direction: an artifact at 0640 owned by root:deploy is readable
// by deploy until a refill lands it root:root.
type access struct {
	perm   uint32
	uid    int
	gid    int
	xattrs map[string][]byte
	acl    []byte
}

// stagedPerm is what a staging file holding a replacement is readable at while
// it is being written: the writer, and nobody else. Zero would be the tighter
// answer and is not usable, because both kernels check an extended-attribute
// call against the file's current mode rather than against the handle, so a
// staging file at 0000 refuses its own owner the ACL it is there to carry.
//
// stagedDirPerm is the same answer for the directory a replacement is staged
// in: the server may enter it and nobody else may. See enclose in local.go for
// why a replacement gets a directory of its own and a fresh object does not.
const (
	stagedPerm    = 0o600
	stagedDirPerm = 0o700
)

// restrictStaged holds a staging inode at perm whatever the umask would have
// clipped it to, and strips every grant it inherited from the directory it was
// created in.
//
// Fchmod alone does not strip one. A macOS ACE carrying file_inherit or
// directory_inherit is copied onto the new inode and grants regardless of the
// mode bits, a Linux default ACL arrives as an access ACL the new inode owns,
// and ZFS at aclmode=passthrough keeps every inherited NFSv4 entry through a
// chmod. Each one hands a reader the replacement body while it is being
// written, under a grant the object being replaced never gave.
func restrictStaged(f *os.File, perm uint32) error {
	fd := int(f.Fd())
	if err := clearACL(fd); err != nil {
		return err
	}
	return unix.Fchmod(fd, perm)
}

// fchown is a seam. The refusal path is what a server without CAP_CHOWN takes
// against an artifact another user owns, and a test cannot create that file
// without being root itself.
var fchown = unix.Fchown

// readAccess reads an object's access state from an open handle rather than
// from its path. A path answers a fresh question every time it is resolved, so
// a mode read from one inode and an ACL read from the next describe a state no
// object ever had; a handle is one inode for as long as it is held.
func readAccess(f *os.File) (a access, err error) {
	fd := int(f.Fd())
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return access{}, err
	}
	a = access{
		// The permission bits and the three above them. Go's FileMode spells
		// setuid somewhere else entirely, so the raw mode is what travels.
		perm:   uint32(st.Mode) & 0o7777,
		uid:    int(st.Uid),
		gid:    int(st.Gid),
		xattrs: map[string][]byte{},
	}
	if a.acl, err = readACL(fd); err != nil {
		return access{}, err
	}
	names, err := listXattr(fd)
	if err != nil {
		return access{}, err
	}
	for _, name := range names {
		v, err := getXattr(fd, name)
		if missingXattr(err) {
			continue
		}
		if err != nil {
			return access{}, fmt.Errorf("read attribute %s: %w", name, err)
		}
		a.xattrs[name] = v
	}
	return a, nil
}

// applyTo gives the staging handle the access state of the object it is about
// to replace, and refuses the publication when it cannot. Order matters:
// chown drops the attributes the kernel treats as privileged, so it goes
// first, and the ACL goes last because chmod rewrites an NFSv4 ACL. ZFS at its
// default aclmode=discard drops every entry the mode cannot express on any
// chmod, the same mode included, so a deny entry applied before the mode is
// gone by the time the object lands; restricted refuses the chmod instead.
// cp -p puts the mode on before the ACL for the same reason. The staging file
// sits in an enclosure nothing else can traverse while it holds the object's
// mode without its ACL, and the rename out of it happens after both.
func (a access) applyTo(f *os.File, key string) error {
	fd := int(f.Fd())
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if int(st.Uid) != a.uid || int(st.Gid) != a.gid {
		if err := fchown(fd, a.uid, a.gid); err != nil {
			return fmt.Errorf("publish %s: the replacement cannot be given the %d:%d ownership the object already has (%w); "+
				"the previous object is unchanged. Run bodega as that user, or give the storage tree to the user it runs as", key, a.uid, a.gid, err)
		}
	}
	if err := a.restoreXattrs(fd, key); err != nil {
		return err
	}
	if err := unix.Fchmod(fd, a.perm); err != nil {
		return fmt.Errorf("publish %s: the replacement cannot be set to the object's mode %04o (%w); the previous object is unchanged", key, a.perm, err)
	}
	if err := applyACL(fd, a.acl); err != nil {
		return fmt.Errorf("publish %s: the replacement cannot carry the object's ACL (%w); the previous object is unchanged", key, err)
	}
	return nil
}

// restoreXattrs makes the staging file's attributes the object's attributes,
// both directions. Removing is not housekeeping: an attribute on the staging
// file that the object never had is a decision nobody made, and an access ACL
// is the case where that denies readers the object allowed. A replacement is
// staged in an enclosure stripped of its inheritance, so nothing should reach
// here carrying one; this is the check that the enclosure held, and the only
// one that runs against the inode rather than against the directory above it.
func (a access) restoreXattrs(fd int, key string) error {
	staged, err := listXattr(fd)
	if err != nil {
		return err
	}
	for _, name := range staged {
		if _, keep := a.xattrs[name]; keep {
			continue
		}
		if err := unix.Fremovexattr(fd, name); err != nil && !missingXattr(err) {
			return fmt.Errorf("publish %s: the replacement cannot drop the %s attribute it inherited (%w); the previous object is unchanged", key, name, err)
		}
	}
	for name, want := range a.xattrs {
		if got, err := getXattr(fd, name); err == nil && string(got) == string(want) {
			continue
		}
		if err := unix.Fsetxattr(fd, name, want, 0); err != nil {
			return fmt.Errorf("publish %s: the replacement cannot carry the object's %s attribute (%w), which is where an access ACL lives; "+
				"the previous object is unchanged", key, name, err)
		}
	}
	return nil
}

func getXattr(fd int, name string) ([]byte, error) {
	for range 10 {
		size, err := unix.Fgetxattr(fd, name, nil)
		if err != nil {
			return nil, err
		}
		buf := make([]byte, size)
		n, err := unix.Fgetxattr(fd, name, buf)
		if errors.Is(err, unix.ERANGE) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return buf[:n], nil
	}
	return nil, fmt.Errorf("read extended attribute %s: the value kept changing under the read", name)
}

// unsupportedXattr reports a filesystem that holds no extended attributes at
// all, which is not a failure to preserve the ones an object does not have.
func unsupportedXattr(err error) bool {
	return errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) || missingXattr(err)
}

// missingXattr reports an attribute the file does not carry, which a list and
// a read of the same file disagree about whenever another process is writing.
func missingXattr(err error) bool {
	return errors.Is(err, errNoAttr)
}
