//go:build !linux

package host

// CheckSnapd is a no-op on non-Linux platforms. snapd does not ship on
// macOS or Windows hosts in practice.
func CheckSnapd() Finding {
	return Finding{
		Check:  "snapd",
		Status: StatusNA,
		Detail: "snapd is Linux-only; check not applicable on this platform",
	}
}
