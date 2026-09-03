//go:build linux

package host

import "os"

// CheckFlatpak reports whether flatpak is present. Same failure modes as
// snap: bundled runtimes that bodega does not see, plus remotes (flathub
// etc.) that are configured directly on the host rather than through
// bodega's allow-list.
func CheckFlatpak() Finding {
	f := Finding{Check: "flatpak"}

	systemInstall := exists("/var/lib/flatpak")
	home, _ := os.UserHomeDir()
	userInstall := home != "" && exists(home+"/.local/share/flatpak")

	switch {
	case systemInstall && userInstall:
		f.Status = StatusFail
		f.Detail = "flatpak installed system-wide and per-user; remotes are configured outside bodega's allow-list"
		f.Remediation = "flatpak uninstall --all; apt purge flatpak"
	case systemInstall:
		f.Status = StatusFail
		f.Detail = "flatpak installed system-wide at /var/lib/flatpak"
		f.Remediation = "apt purge flatpak"
	case userInstall:
		f.Status = StatusWarn
		f.Detail = "flatpak per-user installation at ~/.local/share/flatpak"
		f.Remediation = "flatpak uninstall --user --all"
	default:
		f.Status = StatusOK
		f.Detail = "no flatpak installation detected"
	}
	return f
}
