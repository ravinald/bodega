//go:build !linux

package host

func CheckFlatpak() Finding {
	return Finding{
		Check:  "flatpak",
		Status: StatusNA,
		Detail: "flatpak is Linux-only; check not applicable on this platform",
	}
}
