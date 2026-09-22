//go:build linux || darwin || freebsd

package storage

import (
	"encoding/binary"
	"fmt"
)

// FreeBSD's two on-the-disk shapes, held apart from the syscalls in
// acl_freebsd.go and xattr_freebsd.go that hand them to the kernel. They are
// built on every Unix rather than on FreeBSD alone so that the suite covering
// them runs where the suite runs: no FreeBSD host exists to run it on, and a
// layout nothing exercises is how this package reached a release believing
// FreeBSD listed attributes the way Linux does.

// The layout of struct acl from sys/acl.h: acl_maxcnt and acl_cnt, four spare
// ints, then ACL_MAX_ENTRIES + 1 entries of {uint32 tag, uid_t id, uint32
// perm, uint16 entry_type, uint16 flags}. acl_copyout() refuses any buffer
// whose acl_maxcnt is not ACL_MAX_ENTRIES and copies the whole struct out, so
// the blob publication moves between two objects is fixed-size and opaque
// past its first two fields.
const (
	aclMaxEntries = 254
	aclEntrySize  = 16
	aclEntryStart = 24
	aclSize       = aclEntryStart + (aclMaxEntries+1)*aclEntrySize

	tagUserObj  = 0x1  // ACL_USER_OBJ
	tagGroupObj = 0x4  // ACL_GROUP_OBJ
	tagOther    = 0x20 // ACL_OTHER
	undefinedID = 0xFFFFFFFF
)

// blankACL is a struct acl sized for the kernel to copy one out into.
func blankACL() []byte {
	acl := make([]byte, aclSize)
	binary.NativeEndian.PutUint32(acl[:4], aclMaxEntries)
	return acl
}

// minimalACL is the three-entry access ACL equivalent to a set of mode bits:
// the owner, the owning group, everyone else, and nothing named. ACL_READ,
// ACL_WRITE and ACL_EXECUTE are the same three bits in the same order as a
// mode triad, so each triad is its own permission set.
func minimalACL(mode uint32) []byte {
	acl := blankACL()
	binary.NativeEndian.PutUint32(acl[4:8], 3)
	for i, e := range [...]struct{ tag, perm uint32 }{
		{tagUserObj, (mode >> 6) & 7},
		{tagGroupObj, (mode >> 3) & 7},
		{tagOther, mode & 7},
	} {
		off := aclEntryStart + i*aclEntrySize
		binary.NativeEndian.PutUint32(acl[off:off+4], e.tag)
		binary.NativeEndian.PutUint32(acl[off+4:off+8], undefinedID)
		binary.NativeEndian.PutUint32(acl[off+8:off+12], e.perm)
	}
	return acl
}

// checkStructACL refuses a blob __acl_set_fd would answer with EINVAL, which
// unsupportedACL cannot tell from a filesystem that keeps no POSIX.1e ACL at
// all. Whoever reads the error should learn which of the two they have.
func checkStructACL(acl []byte) error {
	if len(acl) != aclSize {
		return fmt.Errorf("%d bytes is not the %d a struct acl occupies", len(acl), aclSize)
	}
	if max := binary.NativeEndian.Uint32(acl[:4]); max != aclMaxEntries {
		return fmt.Errorf("acl_maxcnt is %d, and the kernel copies out only into %d", max, aclMaxEntries)
	}
	if cnt := binary.NativeEndian.Uint32(acl[4:8]); cnt > aclMaxEntries {
		return fmt.Errorf("%d entries is past the %d a struct acl holds", cnt, aclMaxEntries)
	}
	return nil
}

// splitExtattrNames decodes the buffer extattr_list_fd(2) fills, qualifying
// each name with the namespace it was enumerated from.
//
// FreeBSD's buffer is not the NUL-separated list Linux and macOS hand back.
// Each entry is a single byte holding the name's length followed by exactly
// that many bytes, and the name is not NUL-terminated. It also carries no
// namespace, while unix.Fgetxattr splits the name it is given at the first
// '.' and refuses any prefix that is not "user" or "system" (x/sys/unix
// xattr_bsd.go, xattrnamespace), so an unqualified name lifted out of the
// list reads back as ENOATTR and the attribute is dropped in silence.
func splitExtattrNames(buf []byte, prefix string) ([]string, error) {
	var names []string
	for i := 0; i < len(buf); {
		n := int(buf[i])
		i++
		if i+n > len(buf) {
			return nil, fmt.Errorf("list extended attributes: a name %d bytes long starts %d bytes from the end of the answer", n, len(buf)-i)
		}
		if n > 0 {
			names = append(names, prefix+string(buf[i:i+n]))
		}
		i += n
	}
	return names, nil
}
