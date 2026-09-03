//go:build linux

package host

// CheckSnapd reports whether snapd is present on this Linux host. Snap
// auto-refresh and opaque squashfs bundling sit outside bodega's threat
// model — any installed snap can pull arbitrary content from Canonical
// without touching bodega's proxies.
func CheckSnapd() Finding {
	f := Finding{Check: "snapd"}

	socketActive := exists("/run/snapd.socket")
	installed := exists("/var/lib/snapd")
	hasSnaps := exists("/snap")

	switch {
	case socketActive:
		f.Status = StatusFail
		f.Detail = "snapd socket is live at /run/snapd.socket; installed snaps will auto-refresh from Canonical"
		f.Remediation = "systemctl disable --now snapd.socket snapd; apt purge snapd"
	case hasSnaps:
		f.Status = StatusFail
		f.Detail = "snap installations present under /snap; bodega cannot inspect or pin their bundled dependencies"
		f.Remediation = "snap remove <name> for each installed snap, then apt purge snapd"
	case installed:
		f.Status = StatusWarn
		f.Detail = "snapd is installed at /var/lib/snapd but no socket is live"
		f.Remediation = "apt purge snapd to remove the daemon entirely"
	default:
		f.Status = StatusOK
		f.Detail = "no snapd installation detected"
	}
	return f
}
