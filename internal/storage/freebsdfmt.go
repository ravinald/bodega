//go:build linux || darwin || freebsd

package storage

import (
	"encoding/binary"
	"fmt"
)

// FreeBSD's on-the-disk layouts, held apart from the syscalls in
// acl_freebsd.go and xattr_freebsd.go that hand them to the kernel. They are
// built on every Unix rather than on FreeBSD alone so that the suite covering
// them runs where the suite runs: no FreeBSD host exists to run it on, and a
// layout nothing exercises is how this package reached a release believing
// FreeBSD listed attributes the way Linux does.

// The layout of struct acl from sys/acl.h: acl_maxcnt and acl_cnt, four spare
// ints, then ACL_MAX_ENTRIES entries of {uint32 tag, uid_t id, uint32 perm,
// uint16 entry_type, uint16 flags}. acl_copyout() refuses any buffer whose
// acl_maxcnt is not ACL_MAX_ENTRIES and copies the whole struct out, so the
// blob publication moves between two objects is fixed-size.
//
// The same struct carries both kinds of ACL FreeBSD keeps, and nothing inside
// it says which. A POSIX.1e access ACL (UFS mounted -o acls) uses the tag,
// id and perm of each entry and leaves the rest zero. An NFSv4 ACL (ZFS, and
// UFS mounted -o nfsv4acls) adds allow or deny in entry_type and inheritance
// in flags, names everyone@ where POSIX.1e names other and a mask, and draws
// perm from a different set of bits. Handing one to the kernel as the other is
// either refused or read as something the object never said, so the blob
// publication carries is the struct preceded by the acl_type_t it was read as.
const (
	aclMaxEntries = 254
	aclEntrySize  = 16
	aclEntryStart = 24
	aclSize       = aclEntryStart + aclMaxEntries*aclEntrySize

	// UFS stores a POSIX.1e ACL as struct oldacl, and acl_copy_acl_into_oldacl
	// answers EINVAL past OLDACL_MAX_ENTRIES. An NFSv4 ACL is stored whole.
	posix1eMaxEntries = 32

	aclTypeAccess  = 0x2 // ACL_TYPE_ACCESS
	aclTypeDefault = 0x3 // ACL_TYPE_DEFAULT
	aclTypeNFS4    = 0x4 // ACL_TYPE_NFS4
	aclTypeSize    = 4

	tagUserObj  = 0x1  // ACL_USER_OBJ
	tagUser     = 0x2  // ACL_USER
	tagGroupObj = 0x4  // ACL_GROUP_OBJ
	tagGroup    = 0x8  // ACL_GROUP
	tagMask     = 0x10 // ACL_MASK
	tagOther    = 0x20 // ACL_OTHER
	tagEveryone = 0x40 // ACL_EVERYONE
	undefinedID = 0xFFFFFFFF

	entryAllow = 0x0100 // ACL_ENTRY_TYPE_ALLOW
	entryDeny  = 0x0200 // ACL_ENTRY_TYPE_DENY
	entryAudit = 0x0400 // ACL_ENTRY_TYPE_AUDIT
	entryAlarm = 0x0800 // ACL_ENTRY_TYPE_ALARM
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

// aclTypeFor names the one ACL type a filesystem keeps, from its answers to
// fpathconf(_PC_ACL_NFS4) and fpathconf(_PC_ACL_EXTENDED). Zero means it keeps
// none, which is the only answer that lets publication carry no ACL: a
// filesystem that keeps one and refuses to hand it over is a failure, not an
// object without an ACL.
func aclTypeFor(nfs4, posix1e int) (uint32, error) {
	switch {
	case nfs4 > 0 && posix1e > 0:
		return 0, fmt.Errorf("the filesystem reports both NFSv4 and POSIX.1e ACLs, and an object carries one or the other")
	case nfs4 > 0:
		return aclTypeNFS4, nil
	case posix1e > 0:
		return aclTypeAccess, nil
	}
	return 0, nil
}

// aclTypeName is how an error names an acl_type_t to whoever reads it.
func aclTypeName(aclType uint32) string {
	switch aclType {
	case aclTypeNFS4:
		return "NFSv4"
	case aclTypeAccess:
		return "POSIX.1e"
	case 0:
		return "no"
	}
	return fmt.Sprintf("type %#x", aclType)
}

// tagACL prefixes a struct acl with the type it was read as.
func tagACL(aclType uint32, acl []byte) []byte {
	blob := make([]byte, aclTypeSize, aclTypeSize+len(acl))
	binary.NativeEndian.PutUint32(blob, aclType)
	return append(blob, acl...)
}

// untagACL splits a blob tagACL built back into its type and struct acl, and
// refuses one __acl_set_fd would answer with EINVAL for that type.
func untagACL(blob []byte) (uint32, []byte, error) {
	if len(blob) < aclTypeSize {
		return 0, nil, fmt.Errorf("%d bytes is too short to say which kind of ACL it is", len(blob))
	}
	aclType := binary.NativeEndian.Uint32(blob[:aclTypeSize])
	acl := blob[aclTypeSize:]
	if err := checkStructACL(aclType, acl); err != nil {
		return 0, nil, err
	}
	return aclType, acl, nil
}

// checkStructACL refuses a struct acl __acl_set_fd would answer with EINVAL
// for aclType, which is also the errno a filesystem gives for a type it does
// not keep. Whoever reads the error should learn which of the two they have.
func checkStructACL(aclType uint32, acl []byte) error {
	if len(acl) != aclSize {
		return fmt.Errorf("%d bytes is not the %d a struct acl occupies", len(acl), aclSize)
	}
	if max := binary.NativeEndian.Uint32(acl[:4]); max != aclMaxEntries {
		return fmt.Errorf("acl_maxcnt is %d, and the kernel copies out only into %d", max, aclMaxEntries)
	}
	cnt := binary.NativeEndian.Uint32(acl[4:8])
	var tags uint32
	switch aclType {
	case aclTypeAccess:
		if cnt > posix1eMaxEntries {
			return fmt.Errorf("%d entries is past the %d a POSIX.1e ACL holds", cnt, posix1eMaxEntries)
		}
		tags = tagUserObj | tagUser | tagGroupObj | tagGroup | tagMask | tagOther
	case aclTypeNFS4:
		if cnt == 0 || cnt > aclMaxEntries {
			return fmt.Errorf("%d entries is outside the 1 to %d an NFSv4 ACL holds", cnt, aclMaxEntries)
		}
		tags = tagUserObj | tagUser | tagGroupObj | tagGroup | tagEveryone
	default:
		return fmt.Errorf("acl_type_t %#x is neither a POSIX.1e access ACL nor an NFSv4 ACL", aclType)
	}
	for i := range int(cnt) {
		off := aclEntryStart + i*aclEntrySize
		tag := binary.NativeEndian.Uint32(acl[off : off+4]) //nolint:gosec // G602: len(acl) is aclSize and cnt at most aclMaxEntries, both checked above.
		if tag&tags != tag || tag == 0 || tag&(tag-1) != 0 {
			return fmt.Errorf("entry %d has tag %#x, which a %s ACL does not use", i, tag, aclTypeName(aclType))
		}
		if aclType != aclTypeNFS4 {
			continue
		}
		switch kind := binary.NativeEndian.Uint16(acl[off+12 : off+14]); kind { //nolint:gosec // G602: as above.
		case entryAllow, entryDeny, entryAudit, entryAlarm:
		default:
			return fmt.Errorf("entry %d has entry type %#x, which is not allow, deny, audit or alarm", i, kind)
		}
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
